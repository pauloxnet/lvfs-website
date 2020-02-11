#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: GPL-2.0+
#
# pylint: disable=no-self-use

import os
import sqlite3

from flask import render_template

from lvfs.pluginloader import PluginBase, PluginSettingBool, PluginSettingText, PluginSettingTextList
from lvfs.models import Test
from lvfs.emails import send_email
from lvfs.util import _get_shard_path

class Plugin(PluginBase):
    def __init__(self):
        PluginBase.__init__(self)
        self.name = 'Microcode Notify'
        self.summary = 'Email any unidentified stable microcode to a specific person'
        self.order_after = ['microcode-mcedb']

    def settings(self):
        s = []
        s.append(PluginSettingBool('microcode_notify_enabled', 'Enabled', False))
        s.append(PluginSettingText('microcode_notify_address', 'Email addresses for notification', 'admin@example.com'))
        s.append(PluginSettingText('microcode_notify_mcedb', 'Path to MCE.db', 'MCExtractor/MCE.db'))
        s.append(PluginSettingTextList('microcode_notify_remotes', 'Share microcode in remotes', ['stable', 'testing']))
        return s

    def require_test_for_md(self, md):

        # only run for capsule updates
        if not md.protocol:
            return False
        if not md.blob:
            return False
        return md.protocol.value == 'org.uefi.capsule'

    def ensure_test_for_fw(self, fw):

        # is the firmware not in a correct remote
        remotes = self.get_setting('microcode_notify_remotes', required=True).split(',')
        if fw.remote.name not in remotes:
            return

        # if not already exists
        test = fw.find_test_by_plugin_id(self.id)
        if not test:
            test = Test(plugin_id=self.id, waivable=True)
            fw.tests.append(test)

    def _run_test_on_shard(self, test, shard):

        # only Intel μcode supported at this time
        if shard.guid != '3f0229ad-0a00-5269-90cf-0a45d8781b72':
            return

        # get required attributes
        cpuid = shard.get_attr_value('cpuid')
        if not cpuid:
            return
        platform = shard.get_attr_value('platform')
        if not platform:
            return
        version = shard.get_attr_value('version')
        if not version:
            return

        # load database
        mcefn = self.get_setting('microcode_notify_mcedb', required=True)
        if not os.path.exists(mcefn):
            test.add_fail('cannot locate database: {}'.format(mcefn))
            return
        conn = sqlite3.connect(mcefn)

        # email the admin notifying them about the new microcode
        c = conn.cursor()
        c.execute('SELECT version FROM Intel WHERE cpuid=? AND '
                  'platform=? AND version==? LIMIT 1',
                  (cpuid, platform, version,))
        if not c.fetchone():
            test.add_pass('Not found in MCEdb')
            email_address = self.get_setting('microcode_notify_address')
            if email_address:
                for addr in email_address.split(','):
                    send_email('[LVFS] Microcode not found in MCEdb',
                               addr,
                               render_template('email-microcode-new.txt',
                                               shard=shard))
        c.close()

    def run_test_on_md(self, test, md):
        for shard in md.shards:
            self._run_test_on_shard(test, shard)
