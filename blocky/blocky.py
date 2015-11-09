#!/usr/bin/env python2.7

import commands
import sys

import subprocess

import os
import logging
from ConfigParser import ConfigParser
from dns import resolver
from iptc import Rule, Match, Target, Table

ips = []

logging.basicConfig()
log = logging.getLogger()


# Exceptions

class BlockIPError(Exception):
    pass


class TableNotFound(BlockIPError):
    pass


class ChainNotFound(BlockIPError):
    pass


class IPSetError(BlockIPError):
    pass


class ConfigFileNotFound(Exception):
    pass


# Utilities

def flatten(lst):
    flat = []
    for x in lst:
        if hasattr(x, '__iter__') and not isinstance(x, basestring):
            flat.extend(flatten(x))
        else:
            flat.append(x)
    return flat


class DetectIPAddresses(object):
    def __init__(self, fqdns=[]):
        self.fqdns = fqdns
        self._rslv = resolver.Resolver()

    def iplist(self):
        return flatten([[x.address for x in self._rslv.query(fqdn, 'A')] for fqdn in self.fqdns])


class IPTablesHandler(object):
    def __init__(self, table_name='', chain_name=''):
        self.chain_name = chain_name
        self.table_name = table_name
        self.chain = None
        self.table = None
        self._table_find()
        self._chain_find()
        self.rules()

    def _table_find(self):
        try:
            self.table = Table(getattr(Table, self.table_name))
        except AttributeError as e:
            raise TableNotFound(self.table_name)

    def _chain_find(self):
        chains = filter(lambda c: c.name == self.chain_name, self.table.chains)
        try:
            self.chain = chains[0]
        except IndexError:
            raise ChainNotFound(self.chain_name)

    def rules(self):
        if not self.chain:
            self._chain_find()
        return self.chain.rules



class IPSetHandler(object):
    def __init__(self):
        self.blacklist_name = 'blocky_blacklist'
        self.create_ipset_args = 'create {} hash:ip hashsize 4096'.format(self.blacklist_name)
        self.path = os.environ.get('PATH', '/sbin:/bin:/usr/sbin:/usr/bin')

    def _env(self):
        return {'PATH': self.path, 'LC_ALL': 'C'}

    def create_ipset(self):
        cmds = flatten(['ipset', self.create_ipset_args.split()])
        p = subprocess.Popen(cmds, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self._env())
        so, se = p.communicate()
        if p.returncode:
            if not so and se.find('set with the same name already exists') > -1:
                return
            raise IPSetError(se)


class Settings(object):
    def __init__(self, config_file='/etc/blocky.conf'):
        self.config_file = config_file
        self.settings = {}
        self.list_keys = ['domains']

    def parse_config(self):
        cp = ConfigParser()
        cp.read(self.config_file)
        if not 'main' in cp.sections():
            raise ConfigFileNotFound(self.config_file)
        for opt in cp.options('main'):
            val = cp.get('main', opt)
            if opt in self.list_keys:
                val = [x.strip() for x in val.split(',')]
            self.settings[opt] = val


class StartupChecks(object):
    def __init__(self, table_name='', chain_name=''):
        self.table_name = table_name
        self.chain_name = chain_name

    def test_prereqs(self):
        self.check_root()
        self.check_command_availability()
        self.check_table_and_chain()

    def check_command_availability(self):
        for cmd, args in [('iptables', '-L -n'), ('ipset', '-L -n')]:
            status, err = commands.getstatusoutput('{} {}'.format(cmd, args))
            if status:
                print >> sys.stderr, 'ERROR command {} is missing or otherwise unavailable, exit status: {}, error: {}'.format(
                    cmd, status, err)
                sys.exit(status)

    def check_root(self):
        if os.geteuid():
            print >> sys.stderr, 'This program has to be ran by root. Aborting.'
            sys.exit(1)

    def check_table_and_chain(self):
        th = IPTablesHandler(table_name=self.table_name, chain_name=self.chain_name)
        th._chain_find()


class Main(object):
    def run(self):
        try:
            # Parse config file
            s = Settings()
            s.parse_config()
            settings = s.settings
            table_name = settings.get('table')
            chain_name = settings.get('chain')
            log.debug('Settings: %s', settings)
            # Do startup checks
            sc = StartupChecks(table_name=table_name, chain_name=chain_name)
            sc.test_prereqs()
            # Create ipset
            ish = IPSetHandler()
            ish.create_ipset()
            # Insert iptable rule
            ith = IPTablesHandler(table_name=table_name, chain_name=chain_name)
            det = DetectIPAddresses()
            print det.iplist()
        except ConfigFileNotFound as e:
            log.error('Config file not found or [main] section is missing: %s', e)
            sys.exit(2)
        except TableNotFound as e:
            log.error('Table %s not found', e)
            sys.exit(3)
        except ChainNotFound as e:
            log.error('Chain %s not found in table %s', e, table_name)
            sys.exit(4)
        except IPSetError as e:
            log.error('ipset problem: %s', e)
            sys.exit(5)


if __name__ == '__main__':
    m = Main()
    m.run()
