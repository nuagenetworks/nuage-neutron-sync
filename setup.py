#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='nuageneutronsync',
    version='1.0.1',
    packages=['nuageneutronsync', 'nuageneutronsync.utils', 'nuageneutronsync.operations'],
    data_files=[('/etc/nuage-neutron-sync', ['config/nuage-neutron-sync.conf']),
                ('/etc/init.d', ['config/nuage-neutron-syncd'])],
    url='https://github.com/nuagenetworks/nuage-neutron-sync',
    author='Dieter De Moitie',
    description='Nuage Neutron Sync',
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Environment :: OpenStack',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ),
    entry_points={
        'console_scripts': [
            'nuage-neutron-sync = nuageneutronsync.nuage_neutron_sync:execute'
        ]
    },
    install_requires=[
        'docopt',
        'netaddr',
        'MySQL-python',
        'prettytable',
    ]
)
