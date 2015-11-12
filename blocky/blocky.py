#!/usr/bin/env python2.7

import commands
import sys

import subprocess

import time

import os
import logging
from ConfigParser import ConfigParser
from dns import resolver
from iptc import Rule, Match, Target, Table

ips = []

logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.INFO)


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

class IncorrectCheckEvery(Exception):
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


def set_log_level(log, log_level_name):
    try:
        level = getattr(logging, log_level_name.strip().upper())
        log.setLevel(level)
    except AttributeError:
        log.error('Log level %s not found. Aborting.', log_level_name)
        sys.exit(7)





class DetectIPAddresses(object):
    def __init__(self, fqdns=[]):
        self.fqdns = fqdns
        self._rslv = resolver.Resolver()

    def iplist(self):
        log.debug('FQDNs: %s', self.fqdns)
        addresses = flatten([[x.address for x in self._rslv.query(fqdn, 'A')] for fqdn in self.fqdns])
        uniq = list(set(addresses))
        uniq.sort()
        return uniq


class IPTablesHandler(object):
    def __init__(self, table_name='FILTER', chain_name='FORWARD', ipset_name='blocky'):
        self.chain_name = chain_name
        self.table_name = table_name
        self.ipset_name = ipset_name
        self.chain = None
        self.table = None
        self.rule = None
        self._comment = 'Blocky IPTables Rule'
        self._table_find()
        self._chain_find()
        self._rule_find()

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

    def insert_rule(self):
        if not self.rule:
            rule = Rule()
            rule.protocol = 'tcp'
            rule.target = rule.create_target('DROP')
            match = rule.create_match('comment')
            match.comment = self._comment
            match = rule.create_match('set')
            match.match_set = [self.ipset_name, 'src']
            log.info('''Inserting a rule with target DROP into chain %s (table %s) for ipset "%s" (with comment "%s")''',
                     self.chain_name, self.table_name, self.ipset_name, self._comment)
            self.chain.insert_rule(rule, position=0)

    def _rule_find(self):
        for rule in self.rules():
            match_with_comment = filter(lambda m: m.comment == self._comment, rule.matches)
            if match_with_comment:
                self.rule = rule
                return rule


class IPSetHandler(object):
    def __init__(self, ipset_name='blocky_blacklist'):
        self.ipset_name = ipset_name
        self.create_ipset_args = 'create {} hash:ip hashsize 4096'.format(self.ipset_name)
        self.path = os.environ.get('PATH', '/sbin:/bin:/usr/sbin:/usr/bin')
        self.iplist_prev = []

    def _env(self):
        return {'PATH': self.path, 'LC_ALL': 'C'}

    def run_ipset_cmd(self, cmds):
        p = subprocess.Popen(cmds, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self._env())
        so, se = p.communicate()
        if p.returncode:
            if not so and se.find('set with the same name already exists') > -1:
                return
            raise IPSetError(se)

    def create_ipset(self):
        cmds = flatten(['ipset', self.create_ipset_args.split()])
        self.run_ipset_cmd(cmds)

    def update_ipset(self, iplist):
        iplist.sort()
        if iplist != self.iplist_prev:
            log.info('Updating ipset %s with IP addresses: %s', self.ipset_name, ', '.join(map(str, iplist)))
            cmds = flatten(['ipset', 'flush', self.ipset_name])
            self.run_ipset_cmd(cmds)
            log.debug(cmds)
            for ip in iplist:
                cmds = flatten(['ipset', 'add', self.ipset_name, str(ip)])
                log.debug(cmds)
                self.run_ipset_cmd(cmds)
            self.iplist_prev = iplist



class Settings(object):
    def __init__(self, config_file='/etc/blocky.conf',
                 mandatory_fields=['table', 'chain', 'check_every', 'domains', 'ipset', 'log_level']):
        self._config_file = config_file
        self._list_keys = ['domains']
        self._mandatory_fields = mandatory_fields
        self._parse_config()

    def _parse_config(self):
        cp = ConfigParser()
        cp.read(self._config_file)
        if not 'main' in cp.sections():
            raise ConfigFileNotFound(self._config_file)
        visited = set()
        for opt in cp.options('main'):
            val = cp.get('main', opt)
            if opt in self._list_keys:
                val = [x.strip() for x in val.split(',')]
            setattr(self, opt, val)
            visited.add(opt)
        diff = set(self._mandatory_fields) - visited
        if diff:
            log.error('Following mandatory option(s) are not set in config file %s: %s. Aborting.', self._config_file,
                      ', '.join(map(str, list(diff))))
            sys.exit(6)


class StartupChecks(object):
    def __init__(self, settings):
        self.table_name = settings.table
        self.chain_name = settings.chain
        self.settings = settings

    def test_prereqs(self):
        self.check_int_check_every()
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

    def check_int_check_every(self):
        try:
            ce = int(self.settings.check_every)
        except ValueError:
            raise IncorrectCheckEvery(self.settings.check_every)
        if ce <= 0:
            raise IncorrectCheckEvery(self.settings.check_every)
        self.settings.check_every = ce


class Checkpoint(object):

    def __init__(self, settings):
        self.settings = settings

    def run(self):
        # Create ipset
        ish = IPSetHandler(ipset_name=self.settings.ipset)
        ish.create_ipset()
        # Insert iptables rule
        ith = IPTablesHandler(table_name=self.settings.table, chain_name=self.settings.chain, ipset_name=self.settings.ipset)
        ith.insert_rule()
        delay = int(self.settings.check_every)
        detect = DetectIPAddresses(fqdns=self.settings.domains)
        while True:
            iplist = detect.iplist()
            ish.update_ipset(iplist)
            time.sleep(delay)


class Main(object):
    def run(self):
        try:
            # Parse config file
            settings = Settings()
            log_level_name = settings.log_level
            set_log_level(log, log_level_name)
            # Do startup checks
            sc = StartupChecks(settings)
            sc.test_prereqs()
            cp = Checkpoint(settings)
            cp.run()
        except ConfigFileNotFound as e:
            log.error('Config file not found or [main] section is missing: %s', e)
            sys.exit(2)
        except TableNotFound as e:
            log.error('Table %s not found', e)
            sys.exit(3)
        except ChainNotFound as e:
            log.error('Chain %s not found in table %s', e, settings.table)
            sys.exit(4)
        except IPSetError as e:
            log.error('ipset problem: %s', e)
            sys.exit(5)
        except IncorrectCheckEvery as e:
            log.error('Incorrect check_every setting (%s) in config file. Aborting.', e)
            sys.exit(8)


# TODO: empty ipset on shutdown
# TODO: log blocked ips regularly
# TODO: log blocked ips on change
# TODO: detect rule by comment
# TODO: delete rule on shutdown
# TODO: log to system logger or a file

if __name__ == '__main__':
    m = Main()
    m.run()
