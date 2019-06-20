#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: GPL-2.0+

from lvfs import app

if __name__ == '__main__':
    from flask import Flask
    server = Flask(__name__)
    server.wsgi_app = app
    server.run(host=app.config['IP'], port=app.config['PORT'])
