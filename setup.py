#!/usr/bin/env python

import os

"""Setup script for the pyparsing module distribution."""
from distutils.core import setup

__author__ = 'rolandh'

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(# Distribution meta-data
    name = "freeradius_pysaml2",
    version = "0.0.4",
    description = "FreeRadius python module to be used in Moonshot",
    author = "Roland Hedberg",
    author_email = "roland.hedberg@adm.umu.se",
    license = "MIT License",
    py_modules = ['freeradius_pysaml2','radiusd', "freeradius_ecp"],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        ],
    long_description=read('README'),
    data_files=[('/usr/local/etc/moonshot', ['etc/config.py',
                                             'etc/metadata.xml',
                                             "etc/pysaml_config.py"]),
                ('/usr/local/etc/moonshot/attributemaps',
                            ['attributemaps/basic.py',
                             'attributemaps/saml_uri.py',
                             'attributemaps/shibboleth_uri.py']),
                ('/usr/local/etc/moonshot/pki',
                            ['pki/ssl.cert', 'pki/ssl.key']),
                ('/usr/local/etc/moonshot/template',
                            ['template/modules_python',
                             'template/sites-available_default',
                             'template/sites-available_inner-tunnel'])],
    install_requires=[
        'pysaml2'
    ]
    )
