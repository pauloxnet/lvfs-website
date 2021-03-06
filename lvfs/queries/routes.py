#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: GPL-2.0+

from flask import Blueprint, request, flash, url_for, redirect, render_template, g
from flask_login import login_required

from lvfs import db

from lvfs.models import YaraQuery
from .utils import _async_query_run

bp_queries = Blueprint('queries', __name__, template_folder='templates')

@bp_queries.route('/')
@login_required
def route_list():

    # security check
    if not g.user.check_acl('@yara-query'):
        flash('Permission denied: Unable to list queries', 'danger')
        return redirect(url_for('main.route_dashboard'))
    return render_template('query-list.html', category='firmware')

@bp_queries.route('/new')
@login_required
def route_new():

    # security check
    if not g.user.check_acl('@yara-query'):
        flash('Permission denied: Unable to create queries', 'danger')
        return redirect(url_for('main.route_dashboard'))
    return render_template('query-new.html', category='firmware')

@bp_queries.route('/<int:yara_query_id>')
@login_required
def route_show(yara_query_id):

    # security check
    if not g.user.check_acl('@yara-query'):
        flash('Permission denied: Unable to show query', 'danger')
        return redirect(url_for('main.route_dashboard'))

    # check exists
    query = db.session.query(YaraQuery).filter(YaraQuery.yara_query_id == yara_query_id).first()
    if not query:
        flash('No YARA query found', 'danger')
        return redirect(url_for('main.route_dashboard'))

    # security check
    if not query.check_acl('@show'):
        flash('Permission denied: Unable to show query', 'danger')
        return redirect(url_for('main.route_dashboard'))

    return render_template('query-show.html', category='firmware', query=query)

@bp_queries.route('/<int:yara_query_id>/retry')
@login_required
def route_retry(yara_query_id):

    # security check
    if not g.user.check_acl('@yara-query'):
        flash('Permission denied: Unable to retry queries', 'danger')
        return redirect(url_for('main.route_dashboard'))

    # check exists
    query = db.session.query(YaraQuery).filter(YaraQuery.yara_query_id == yara_query_id).first()
    if not query:
        flash('No query found', 'danger')
        return redirect(url_for('main.route_dashboard'))

    # security check
    if not query.check_acl('@retry'):
        flash('Permission denied: Unable to retry query', 'danger')
        return redirect(url_for('main.route_dashboard'))

    # renew
    query.started_ts = None
    query.ended_ts = None
    db.session.commit()

    # asynchronously run
    _async_query_run.apply_async(args=(query.yara_query_id,), queue='yara', countdown=10)

    flash('YARA query {} will be rerun soon'.format(query.yara_query_id), 'info')
    return redirect(url_for('queries.route_list'))

@bp_queries.route('/<int:yara_query_id>/delete')
@login_required
def route_delete(yara_query_id):

    # security check
    if not g.user.check_acl('@yara-query'):
        flash('Permission denied: Unable to delete queries', 'danger')
        return redirect(url_for('main.route_dashboard'))

    # check exists
    query = db.session.query(YaraQuery).filter(YaraQuery.yara_query_id == yara_query_id).first()
    if not query:
        flash('No query found', 'danger')
        return redirect(url_for('main.route_dashboard'))

    # security check
    if not query.check_acl('@delete'):
        flash('Permission denied: Unable to delete query', 'danger')
        return redirect(url_for('main.route_dashboard'))

    # renew
    db.session.delete(query)
    db.session.commit()
    flash('Deleted YARA query', 'info')
    return redirect(url_for('queries.route_list'))

@bp_queries.route('/create', methods=['POST'])
@login_required
def route_create():

    # security check
    if not g.user.check_acl('@yara-query'):
        flash('Permission denied: Unable to add queries', 'danger')
        return redirect(url_for('main.route_dashboard'))

    # sanity check
    if not 'value' in request.form:
        flash('Unable to add query as no value', 'danger')
        return redirect(url_for('main.route_dashboard'))
    query = db.session.query(YaraQuery).filter(YaraQuery.value == request.form['value']).first()
    if query:
        flash('Already a query with that text!', 'info')
        return redirect(url_for('queries.route_list'))

    query = YaraQuery(value=request.form['value'], user=g.user)
    db.session.add(query)
    db.session.commit()

    # asynchronously run
    _async_query_run.apply_async(args=(query.yara_query_id,), queue='yara', countdown=10)

    flash('YARA query {} added and will be run soon'.format(query.yara_query_id), 'info')
    return redirect(url_for('queries.route_list'), 302)
