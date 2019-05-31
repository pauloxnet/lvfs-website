#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2
#
# pylint: disable=no-self-use

import tempfile
import glob
import os
import re
import subprocess

from app import db
from app.pluginloader import PluginBase, PluginError, PluginSettingBool, PluginSettingText
from app.models import Test, ComponentShard

def _add_component_shards(self, md, files):

    # remove any old shards we added
    for shard in md.shards:
        if shard.plugin_id == self.id:
            db.session.delete(shard)

    # should we write to disk for later processing
    save = self.get_setting_bool('chipsec_write_shards')

    # parse each EFI binary as a shard
    for fn in files:
        sections = fn.rsplit('/')
        name = sections[-1].split('.')[0]
        guid = None
        for section in reversed(sections[:-1]):
            if section.find('GUID_DEFINED') != -1:
                continue
            if section.find('COMPRESSION') != -1:
                continue
            guid = section.split('_')[1].split('.')[0].lower()
            break
        if not guid:
            continue

        shard = ComponentShard(component_id=md.component_id, plugin_id=self.id)
        shard.ensure_info(guid, name)
        with open(fn, 'rb') as f:
            shard.set_blob(f.read(), save=save)

        # add shard to component
        md.shards.append(shard)

def _run_chipsec_on_blob(self, test, md):

    # write firmware to temp file
    cwd = tempfile.TemporaryDirectory(prefix='lvfs')
    src = tempfile.NamedTemporaryFile(mode='wb',
                                      prefix='lvfs_',
                                      suffix=".bin",
                                      dir=cwd.name,
                                      delete=False)
    src.write(md.blob)
    src.flush()

    # run chipsec
    cmd = self.get_setting('chipsec_binary', required=True)
    argv = [cmd, '--no_driver', 'uefi', 'decode', src.name]
    ps = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd.name)
    if ps.wait() != 0:
        raise PluginError('Failed to decode file: %s' % ps.stderr.read())

    # look for shards
    outdir = src.name + '.dir'
    files = glob.glob(outdir + '/FV/**/*.efi', recursive=True)
    if not files:
        test.add_pass('No firmware volumes found in {}'.format(md.filename_contents))
        return
    _add_component_shards(self, md, files)

class Plugin(PluginBase):
    def __init__(self):
        PluginBase.__init__(self)

    def name(self):
        return 'CHIPSEC'

    def summary(self):
        return 'Add firmware shards for UEFI capsules'

    def settings(self):
        s = []
        s.append(PluginSettingBool('chipsec_enabled', 'Enabled', True))
        s.append(PluginSettingBool('chipsec_write_shards', 'Write shards to disk', True))
        s.append(PluginSettingText('chipsec_binary', 'CHIPSEC executable', 'chipsec_util'))
        return s

    def _require_test_for_md(self, md):
        if not md.protocol:
            return False
        return md.protocol.value == 'org.uefi.capsule'

    def _require_test_for_fw(self, fw):
        for md in fw.mds:
            if self._require_test_for_md(md):
                return True
        return False

    def ensure_test_for_fw(self, fw):

        # add if not already exists
        if self._require_test_for_fw(fw):
            test = fw.find_test_by_plugin_id(self.id)
            if not test:
                test = Test(self.id, waivable=True)
                fw.tests.append(test)

    def run_test_on_fw(self, test, fw):

        # run chipsec on the capsule data
        for md in fw.mds:
            if not self._require_test_for_md(md):
                continue
            if not md.blob:
                continue
            _run_chipsec_on_blob(self, test, md)
        db.session.commit()