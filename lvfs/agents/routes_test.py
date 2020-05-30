#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: GPL-2.0+
#
# pylint: disable=wrong-import-position,singleton-comparison

import os
import sys
import unittest

sys.path.append(os.path.realpath('.'))

from lvfs.testcase import LvfsTestCase

class LocalTestCase(LvfsTestCase):

    def _agent_post(self, endpoint, machine_id='deadbeef'):
        json = """{
          "ReportVersion" : 1,
          "MachineId" : "%s"
        }""" % machine_id
        return self.app.post('/lvfs/agents/{}'.format(endpoint), data=json, follow_redirects=True)

    def test_agent_register_unregister(self):

        # all without logging in
        rv = self._agent_post('unregister')
        assert b'agent is not registered' in rv.data, rv.data
        rv = self._agent_post('register')
        assert b'agent registered' in rv.data, rv.data
        rv = self._agent_post('sync')
        assert b'agent updated' in rv.data, rv.data
        rv = self._agent_post('sync')
        assert b'agent updated' in rv.data, rv.data
        rv = self._agent_post('unregister')
        assert b'agent unregistered' in rv.data, rv.data

if __name__ == '__main__':
    unittest.main()
