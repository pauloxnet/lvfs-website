#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2018 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: GPL-2.0+
#
# pylint: disable=too-many-locals

import os
import datetime
import hashlib

from flask import Blueprint, request, flash, url_for, redirect, render_template, g
from flask_login import login_required
from sqlalchemy import or_

from lvfs import app, db, ploader, csrf

from lvfs.emails import send_email
from lvfs.models import Firmware, FirmwareEvent, Vendor, Remote, Agreement
from lvfs.models import Affiliation, Protocol, Category, Component, Verfmt
from lvfs.tests.utils import _async_test_run_for_firmware
from lvfs.upload.uploadedfile import UploadedFile, FileTooLarge, FileTooSmall, FileNotSupported, MetadataInvalid
from lvfs.util import _get_client_address, _get_settings, _fix_component_name
from lvfs.util import _error_internal
from lvfs.firmware.utils import _firmware_delete, _async_sign_fw

bp_upload = Blueprint('upload', __name__, template_folder='templates')

def _get_plugin_metadata_for_uploaded_file(ufile):
    settings = _get_settings()
    metadata = {}
    metadata['$DATE$'] = datetime.datetime.now().replace(microsecond=0).isoformat()
    metadata['$FWUPD_MIN_VERSION$'] = ufile.fwupd_min_version
    metadata['$CAB_FILENAME$'] = ufile.fw.filename
    metadata['$FIRMWARE_BASEURI$'] = settings['firmware_baseuri']
    return metadata

def _user_can_upload(user):

    # never signed anything
    if not user.agreement:
        return False

    # is it up to date?
    agreement = db.session.query(Agreement).\
                    order_by(Agreement.version.desc()).first()
    if not agreement:
        return False
    if user.agreement.version < agreement.version:
        return False

    # works for us
    return True

def _filter_fw_by_id_guid_version(fws, component_id, provides_value, release_version):
    for fw in fws:
        if fw.is_deleted:
            continue
        for md in fw.mds:
            if md.component_id != component_id:
                continue
            for guid in md.guids:
                if guid.value == provides_value and md.version == release_version:
                    return fw
    return None

def _upload_firmware():

    # verify the user can upload
    if not _user_can_upload(g.user):
        flash('User has not signed legal agreement', 'danger')
        return redirect(url_for('main.route_dashboard'))

    # used a custom vendor_id
    if 'vendor_id' in request.form:
        try:
            vendor_id = int(request.form['vendor_id'])
        except ValueError as e:
            flash('Failed to upload file: Specified vendor ID %s invalid' % request.form['vendor_id'], 'warning')
            return redirect(url_for('upload.route_firmware'))
        vendor = db.session.query(Vendor).filter(Vendor.vendor_id == vendor_id).first()
        if not vendor:
            flash('Failed to upload file: Specified vendor ID not found', 'warning')
            return redirect(url_for('upload.route_firmware'))
    else:
        vendor = g.user.vendor

    # security check
    if not vendor.check_acl('@upload'):
        flash('Permission denied: Failed to upload file for vendor: '
              'User with vendor %s cannot upload to vendor %s' %
              (g.user.vendor.group_id, vendor.group_id), 'warning')
        return redirect(url_for('upload.route_firmware'))

    # not correct parameters
    if not 'target' in request.form:
        return _error_internal('No target')
    if not 'file' in request.files:
        return _error_internal('No file')
    if request.form['target'] not in ['private', 'embargo', 'testing']:
        return _error_internal('Target not valid')

    # find remote, creating if required
    remote_name = request.form['target']
    if remote_name == 'embargo':
        remote = vendor.remote
    else:
        remote = db.session.query(Remote).filter(Remote.name == remote_name).first()
    if not remote:
        return _error_internal('No remote for target %s' % remote_name)

    # if the vendor has uploaded a lot of firmware don't start changing the rules
    is_strict = len(vendor.fws) < 500

    # load in the archive
    fileitem = request.files['file']
    if not fileitem:
        return _error_internal('No file object')
    try:
        ufile = UploadedFile(is_strict=is_strict)
        for cat in db.session.query(Category):
            ufile.category_map[cat.value] = cat.category_id
        for pro in db.session.query(Protocol):
            ufile.protocol_map[pro.value] = pro.protocol_id
        for verfmt in db.session.query(Verfmt):
            ufile.version_formats[verfmt.value] = verfmt
        ufile.parse(os.path.basename(fileitem.filename), fileitem.read())
    except (FileTooLarge, FileTooSmall, FileNotSupported, MetadataInvalid) as e:
        flash('Failed to upload file: ' + str(e), 'danger')
        return redirect(request.url)

    # check the file does not already exist
    fw = db.session.query(Firmware)\
                   .filter(or_(Firmware.checksum_upload_sha1 == ufile.fw.checksum_upload_sha1,
                               Firmware.checksum_upload_sha256 == ufile.fw.checksum_upload_sha256)).first()
    if fw:
        if fw.check_acl('@view'):
            flash('Failed to upload file: A file with hash %s already exists' % fw.checksum_upload_sha1, 'warning')
            return redirect('/lvfs/firmware/%s' % fw.firmware_id)
        flash('Failed to upload file: Another user has already uploaded this firmware', 'warning')
        return redirect(url_for('upload.route_firmware'))

    # check the guid and version does not already exist
    fws = db.session.query(Firmware).all()
    fws_already_exist = []
    for md in ufile.fw.mds:
        provides_value = md.guids[0].value
        fw = _filter_fw_by_id_guid_version(fws,
                                           md.appstream_id,
                                           provides_value,
                                           md.version)
        if fw:
            fws_already_exist.append(fw)

    # all the components existed, so build an error out of all the versions
    if len(fws_already_exist) == len(ufile.fw.mds):
        if g.user.check_acl('@robot') and 'auto-delete' in request.form:
            for fw in fws_already_exist:
                if fw.remote.is_public:
                    flash('Firmware {} cannot be autodeleted as is in remote {}'.format(
                        fw.firmware_id, fw.remote.name), 'danger')
                    return redirect(url_for('upload.route_firmware'))
                if fw.user.user_id != g.user.user_id:
                    flash('Firmware was not uploaded by this user', 'danger')
                    return redirect(url_for('upload.route_firmware'))
            for fw in fws_already_exist:
                flash('Firmware %i was auto-deleted due to robot upload' % fw.firmware_id)
                _firmware_delete(fw)
        else:
            versions_for_display = []
            for fw in fws_already_exist:
                for md in fw.mds:
                    if not md.version_display in versions_for_display:
                        versions_for_display.append(md.version_display)
            flash('Failed to upload file: A firmware file for this device with '
                  'version %s already exists' % ','.join(versions_for_display), 'danger')
            return redirect('/lvfs/firmware/%s' % fw.firmware_id)

    # check if the file dropped a GUID previously supported
    for umd in ufile.fw.mds:
        new_guids = [guid.value for guid in umd.guids]
        for md in db.session.query(Component).\
                        filter(Component.appstream_id == umd.appstream_id):
            if md.fw.is_deleted:
                continue
            for old_guid in [guid.value for guid in md.guids]:
                if old_guid in new_guids:
                    continue
                fw_str = str(md.fw.firmware_id)
                if g.user.check_acl('@qa') or g.user.check_acl('@robot'):
                    flash('Firmware drops GUID {} previously supported '
                          'in firmware {}'.format(old_guid, fw_str), 'warning')
                else:
                    flash('Firmware would drop GUID {} previously supported '
                          'in firmware {}'.format(old_guid, fw_str), 'danger')
                    return redirect(request.url)

    # allow plugins to copy any extra files from the source archive
    for cffile in ufile.cabarchive_upload.values():
        ploader.archive_copy(ufile.cabarchive_repacked, cffile)

    # allow plugins to add files
    ploader.archive_finalize(ufile.cabarchive_repacked,
                             _get_plugin_metadata_for_uploaded_file(ufile))

    # dump to a file
    download_dir = app.config['DOWNLOAD_DIR']
    if not os.path.exists(download_dir):
        os.mkdir(download_dir)
    fn = os.path.join(download_dir, ufile.fw.filename)
    cab_data = ufile.cabarchive_repacked.save(compress=True)
    with open(fn, 'wb') as f:
        f.write(cab_data)

    # create parent firmware object
    settings = _get_settings()
    target = request.form['target']
    fw = ufile.fw
    fw.vendor = vendor
    fw.vendor_odm = g.user.vendor
    fw.user = g.user
    fw.addr = _get_client_address()
    fw.remote = remote
    fw.checksum_signed_sha1 = hashlib.sha1(cab_data).hexdigest()
    fw.checksum_signed_sha256 = hashlib.sha256(cab_data).hexdigest()
    fw.is_dirty = True
    fw.failure_minimum = settings['default_failure_minimum']
    fw.failure_percentage = settings['default_failure_percentage']

    # fix name
    for md in fw.mds:
        name_fixed = _fix_component_name(md.name, md.developer_name_display)
        if name_fixed != md.name:
            flash('Fixed component name from "%s" to "%s"' % (md.name, name_fixed), 'warning')
            md.name = name_fixed

    # verify each component has a version format
    for md in fw.mds:
        if not md.verfmt_with_fallback:
            flash('Component {} does not have required LVFS::VersionFormat'.\
                  format(md.appstream_id), 'warning')

    # add to database
    fw.events.append(FirmwareEvent(remote_id=remote.remote_id, user_id=g.user.user_id))
    db.session.add(fw)
    db.session.commit()

    # ensure the test has been added for the firmware type
    ploader.ensure_test_for_fw(fw)

    # sync everything we added
    db.session.commit()

    # asynchronously run
    _async_test_run_for_firmware.apply_async(args=(fw.firmware_id,))

    # send out emails to anyone interested
    for u in fw.get_possible_users_to_email:
        if u == g.user:
            continue
        if u.get_action('notify-upload-vendor') and u.vendor == fw.vendor:
            send_email("[LVFS] Firmware has been uploaded",
                       u.email_address,
                       render_template('email-firmware-uploaded.txt',
                                       user=u, user_upload=g.user, fw=fw))
        elif u.get_action('notify-upload-affiliate'):
            send_email("[LVFS] Firmware has been uploaded by affiliate",
                       u.email_address,
                       render_template('email-firmware-uploaded.txt',
                                       user=u, user_upload=g.user, fw=fw))

    flash('Uploaded file %s to %s' % (ufile.fw.filename, target), 'info')

    # asynchronously sign
    _async_sign_fw.apply_async(args=(fw.firmware_id,), queue='firmware')

    # invalidate
    if target == 'embargo':
        remote.is_dirty = True
        g.user.vendor.remote.is_dirty = True
        db.session.commit()

    return redirect(url_for('firmware.route_show', firmware_id=fw.firmware_id))

@bp_upload.route('/', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def route_robot():
    """ Upload a .cab file to the LVFS service from a robot user """

    # old URL being used
    if request.method != 'POST':
        return redirect(url_for('upload.route_firmware'))

    # check is robot
    if not g.user.check_acl('@robot'):
        flash('Not a robot user, please try again')
        return redirect(url_for('upload.route_firmware'))

    # continue with form data
    return _upload_firmware()

@bp_upload.route('/firmware', methods=['GET', 'POST'])
@login_required
def route_firmware():
    """ Upload a .cab file to the LVFS service """

    # only accept form data
    if request.method != 'POST':
        if not hasattr(g, 'user'):
            return redirect(url_for('main.route_index'))
        if not _user_can_upload(g.user):
            return redirect(url_for('agreements.route_show'))
        vendor_ids = [res.value for res in g.user.vendor.restrictions]
        affiliations = db.session.query(Affiliation).\
                        filter(Affiliation.vendor_id_odm == g.user.vendor_id).all()
        return render_template('upload.html',
                               category='firmware',
                               vendor_ids=vendor_ids,
                               affiliations=affiliations)

    # continue with form data
    return _upload_firmware()
