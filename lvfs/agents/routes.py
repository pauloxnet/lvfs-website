#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2020 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: GPL-2.0+

import json
import datetime

from flask import Blueprint, request, url_for, redirect, flash, Response, render_template, g
from flask_login import login_required

from lvfs import db, csrf

from lvfs.models import Agent, AgentApproval, AgentDevice
from lvfs.util import _json_success, _json_error, _get_client_address, _event_log
from lvfs.util import admin_login_required

bp_agent = Blueprint('agents', __name__, template_folder='templates')

@bp_agent.route('/')
@login_required
@admin_login_required
def route_list():
    agents = db.session.query(Agent).\
                    order_by(Agent.agent_id.desc()).all()
    return render_template('agent-list.html', agents=agents)

@bp_agent.route('/<int:agent_id>/details')
@login_required
@admin_login_required
def route_details(agent_id):
    agent = db.session.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        flash('Agent does not exist', 'warning')
        return redirect(url_for('agents.route_list'), 302)
    return render_template('agent-details.html', agent=agent)

@bp_agent.route('/<int:agent_id>/delete')
@login_required
@admin_login_required
def route_delete(agent_id):
    agent = db.session.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        flash('Agent does not exist', 'warning')
        return redirect(url_for('agents.route_list'), 302)
    db.session.delete(agent)
    db.session.commit()
    flash('Deleted agent', 'info')
    return redirect(url_for('.agent_list'))

@bp_agent.route('/<int:agent_id>/approval/<checksum>/add')
@login_required
@admin_login_required
def route_approval_add(agent_id, checksum):

    # check does not already exist
    approval = db.session.query(AgentApproval).\
                    filter(AgentApproval.checksum == checksum).\
                    filter(AgentApproval.agent_id == agent_id).\
                    first()
    if approval:
        flash('AgentApproval {} already exists for this agent'.format(checksum), 'warning')
        return redirect(url_for('.route_details', agent_id=agent_id))
    approval = AgentApproval(checksum=checksum, agent_id=agent_id, user_id=g.user.user_id)
    db.session.add(approval)
    db.session.commit()

    # success
    _event_log('Added approval for {} for agent {}'.format(checksum, agent_id))
    return redirect(url_for('.route_details', agent_id=agent_id))

@bp_agent.route('/<int:agent_id>/action/<fwupd_id>/<checksum>/add')
@login_required
@admin_login_required
def route_action_add(agent_id, fwupd_id, checksum):

    # success
    _event_log('Added action for {}:{} for agent {}'.format(checksum, fwupd_id, agent_id))
    return redirect(url_for('.route_details', agent_id=agent_id))

# no login required
@bp_agent.route('/register', methods=['POST'])
@csrf.exempt
def route_register():

    # parse JSON data
    json_request = request.data.decode('utf8')
    try:
        item = json.loads(json_request)
    except ValueError as e:
        return _json_error('No JSON object could be decoded: ' + str(e))

    # check we got enough data
    for key in ['ReportVersion', 'MachineId']:
        if not key in item:
            return _json_error('invalid data, expected %s' % key)
        if item[key] is None:
            return _json_error('missing data, expected %s' % key)

    # parse only this version
    if item['ReportVersion'] != 1:
        return _json_error('version not supported')

    # add each firmware agent
    machine_id = item['MachineId']

    # update any old agent
    agent = db.session.query(Agent).filter(Agent.machine_id == machine_id).first()
    if agent:
        return _json_error('agent is already registered')

    # save a new agent in the database
    agent = Agent(machine_id=machine_id, addr=_get_client_address())
    db.session.add(agent)
    db.session.commit()

    # success
    _event_log('Registered agent %s' % machine_id)
    return _json_success('agent registered')

# no login required
@bp_agent.route('/unregister', methods=['POST'])
@csrf.exempt
def route_unregister():

    # parse JSON data
    json_request = request.data.decode('utf8')
    try:
        item = json.loads(json_request)
    except ValueError as e:
        return _json_error('No JSON object could be decoded: ' + str(e))

    # check we got enough data
    for key in ['ReportVersion', 'MachineId']:
        if not key in item:
            return _json_error('invalid data, expected %s' % key)
        if item[key] is None:
            return _json_error('missing data, expected %s' % key)

    # parse only this version
    if item['ReportVersion'] != 1:
        return _json_error('version not supported')

    # add each firmware agent
    machine_id = item['MachineId']

    # find agent
    agent = db.session.query(Agent).filter(Agent.machine_id == machine_id).first()
    if not agent:
        return _json_error('agent is not registered')

    # delete agent from the database
    db.session.delete(agent)
    db.session.commit()

    # success
    _event_log('Unregistered agent %s' % machine_id)
    return _json_success('agent unregistered')

# no login required
@bp_agent.route('/sync', methods=['POST'])
@csrf.exempt
def route_sync():

    # parse JSON data
    json_request = request.data.decode('utf8')
    try:
        item = json.loads(json_request)
    except ValueError as e:
        return _json_error('No JSON object could be decoded: ' + str(e))

    # check we got enough data
    for key in ['ReportVersion', 'MachineId']:
        if not key in item:
            return _json_error('invalid data, expected %s' % key)
        if item[key] is None:
            return _json_error('missing data, expected %s' % key)

    # parse only this version
    if item['ReportVersion'] != 1:
        return _json_error('version not supported')

    # find agent
    machine_id = item['MachineId']
    agent = db.session.query(Agent).filter(Agent.machine_id == machine_id).first()
    if not agent:
        return _json_error('agent is not already registered')

    # update database
    item = json.loads(json_request)
    agent.devices.clear()
    if 'Devices' in item:
        for device_item in item['Devices']:
            dev = AgentDevice()
            dev.from_json(device_item)
            if not dev.updatable:
                continue
            agent.devices.append(dev)
    agent.timestamp = datetime.datetime.utcnow()
    db.session.commit()

    # get current approved checksums
    checksums = []
    for approval in agent.approvals:
        checksums.append(approval.checksum)

    # get any agent actions
    actions = []
    if len(checksums) == 999:
        action = {}
        action['Task'] = 'upgrade'
        action['DeviceId'] = '4588a84d1cfa1ddb273e9df28f6a44927e9b4e99'
        action['Checksum'] = '0e7e9dafeb4dcc144d1434759ebf7bd71ea2a4d7'
        actions.append(action)

    # return blob
    item = {}
    item['success'] = True
    if checksums:
        item['approved'] = checksums
    if actions:
        item['actions'] = actions
    item['msg'] = 'agent updated'
    dat = json.dumps(item, sort_keys=True, indent=4, separators=(',', ': '))
    return Response(response=dat,
                    status=200,
                    mimetype="application/json")
