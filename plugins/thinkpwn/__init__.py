#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: GPL-2.0+
#
# pylint: disable=no-self-use,no-member,too-few-public-methods

import os
import tempfile

import r2pipe

from lvfs import db
from lvfs.pluginloader import PluginBase, PluginError, PluginSettingBool
from lvfs.models import Test

# Do not load r2 plugins to speedup startup times
os.environ['R2_NOPLUGINS'] = '1'

# you might want to change these paramenetrs to tune the heuristics
BB_COUNT = 3
MAX_INSN = 10
MIN_INSN = 3

# lookup for one or all of the specified GUIDs inside file contents
def has_guid(blob):
    for guid in [b'\x4D\x95\x90\x13\x95\xDA\x27\x42\x93\x28\x72\x82\xC2\x17\xDA\xA8',
                 b'\xE2\xD8\x8E\xC6\xC6\x9D\xBD\x4C\x9D\x94\xDB\x65\xAC\xC5\xC3\x32',
                 b'\x6C\xE3\x28\xF3\xB6\x23\x95\x4A\x85\x4B\x32\xE1\x95\x34\xCD\x75']:
        if blob.find(guid) != -1:
            return True
    return False

def insn_uses_global(op):

    if op['type'] == 'mov':

        # get global variable information if MOV instruction is using it
        return (op['esil'].find('rip,+,[8]') != -1, op['esil'].find('=[') != -1)

    # not a MOV instruction
    return (0, 0)

class BasicBlock():

    def __init__(self, r2, addr, size, insn_num):

        self.addr, self.size = addr, size
        self.insn_num = insn_num

        self.calls_total, self.calls_matched = 0, 0
        self.glob_reads, self.glob_writes = 0, 0

        # disassemble basic block
        r2ops = r2.cmdj('aoj %d @ 0x%x' % (insn_num, addr))

        # update instructions information
        for op in r2ops:

            # check for the CALL instruction
            self.check_call(op)

            # check for the MOV instruction with global variable as operand
            self.check_glob(op)

    def check_call(self, op):

        if op['type'] == 'call':

            # regular function call
            self.calls_total += 1

        elif op['type'] == 'ucall' and op['opcode'].find('[') != -1:

            # call function by pointer
            self.calls_total += 1
            self.calls_matched += 1

    def check_glob(self, op):

        # check if instruction reads or writes some global variable
        r, w = insn_uses_global(op)
        if r:
            self.glob_reads += 1
        if w:
            self.glob_writes += 1

def match_func(r2, addr):

    bb_all = []

    # obtain list of basic blocks for given function
    bb_list = r2.cmdj('afbj %s' % addr)
    if len(bb_list) != BB_COUNT:
        return False

    for bb in bb_list:

        insn_num = bb['ninstr']

        # check basic block for proper amount of instruction
        if insn_num > MAX_INSN or insn_num < MIN_INSN:
            return False

        # analyze basic block
        bb = BasicBlock(r2, bb['addr'], bb['size'], insn_num)
        bb_all.append(bb)

    # check calls and global variables usage for each basic block
    if bb_all[0].calls_total != 0 or bb_all[0].calls_matched != 0:
        return False
    if bb_all[0].glob_reads != 0 or bb_all[0].glob_writes != 0:
        return False

    if bb_all[1].calls_total != 1 or bb_all[1].calls_matched != 1:
        return False
    if bb_all[1].glob_reads != 1 or bb_all[1].glob_writes != 0:
        return False

    if bb_all[2].calls_total != 0 or bb_all[2].calls_matched != 0:
        return False
    if bb_all[2].glob_reads != 0 or bb_all[2].glob_writes != 0:
        return False

    # vulnerable function was matched!
    return True

class Plugin(PluginBase):
    def __init__(self, plugin_id=None):
        PluginBase.__init__(self, plugin_id)
        self.name = 'ThinkPwn'
        self.summary = 'Check the EFI binary for the ThinkPwn vulnerability'

    def order_after(self):
        return ['chipsec']

    def settings(self):
        s = []
        s.append(PluginSettingBool('thinkpwn_enabled', 'Enabled', True))
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

    def _run_test_on_shard(self, test, shard):

        # check if suitable
        if shard.blob[0:2] != b'MZ':
            return
        if not has_guid(shard.blob):
            return

        # write certificate to temp file
        crt = tempfile.NamedTemporaryFile(mode='wb',
                                          prefix='thinkpwn_',
                                          suffix=".efi",
                                          dir=None,
                                          delete=True)
        crt.write(shard.blob)
        crt.flush()

        # start radare instance
        r2 = r2pipe.open(crt.name)

        # perform initial analysis
        r2.cmd('aa;aad')

        # enumerate available functions
        for addr in r2.cmdj('aflqj'):

            # check for vulnerable function
            if match_func(r2, addr):
                test.add_fail(shard.name,
                              'Contains ThinkPwn vulnerability @{}'.\
                              format(addr))

        # close radare instance
        r2.quit()

    def run_test_on_fw(self, test, fw):

        # run analysis on each shard
        for md in fw.mds:
            if not self._require_test_for_md(md):
                continue
            for shard in md.shards:
                if shard.blob:
                    self._run_test_on_shard(test, shard)
