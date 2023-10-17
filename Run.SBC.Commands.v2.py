#!/usr/bin/python3
# coding utf-8

import sys
import time
import json
from pathlib import *
import threading
# import random
import passepass
from pysnmp.hlapi import *
import pexpect
import time
from BBC_Parser import BBC_Parser, BBC_field
import re


class MyThread(threading.Thread):
    def __init__(self, node, ip, cmdes, delay, log = False):
        threading.Thread.__init__(self)
        self.hostname = node
        self.ip = ip
        self.exec = list()
        self.cmdes = cmdes
        self.log = log
        self.delay = delay
        self.logfile = sys.stdout
        self.user = 'murdesconfs'
        self.promptShell = [pexpect.EOF, pexpect.TIMEOUT, r'(PV|SR)\w{3}\d{3}.*#', r'>:',r'selection:', r'sftp> ', r'\(y/n\) ', r'\[y/n\]\?: ']
        self.promptPasswd = [r'^.*assword:',
                            'Are you sure you want to continue connecting (yes/no)?']
    def run(self):
        # print(f'Exécution du thread de {self.hostname}, {self.ip}, {self.cmdes}, {self.log}')
        password = passepass.getpass(self.user, 'getpass.priv.ztc.rbci.orange.net')
        cmde = self.cmdes[0]
        if '<user>' in cmde:
            cmde = cmde.replace('<user>', self.user)
        if '<ip>' in cmde:
            cmde = cmde.replace('<ip>', self.ip)

        child = pexpect.spawnu(cmde, timeout=self.delay)
        myDate = time.strftime("%Y%m%d%H%M%S", time.localtime(time.time()))
        if not self.log:
            filename = f'{self.hostname}.{myDate}.exec.log'
            self.logfile = open(filename, 'w')
        child.logfile = self.logfile
        index = child.expect(self.promptPasswd)
        if index == 1:
            child.sendline('yes')
        child.logfile = None
        child.sendline(password)
        child.logfile = self.logfile
        index = child.expect(self.promptShell)
        if index == 0:
            print(f'Erreur, fin de fichier rencontrée')
        elif index == 1:
            print(f'Erreur, délai dépassé pour la commande {cmde}')

        for cmde in self.cmdes[1:]:
            if '<file:' in cmde:
                m = re.search(r'(<file:(.*)>)', cmde)
                if m:
                    cmde = cmde.replace(f'{m.group(1)}', f'{self.hostname}.{myDate}.{m.group(2)}')
                    # print(f'{self.hostname}.{myDate}.{m.group(2)}')               
            child.sendline(cmde)
            index = child.expect(self.promptShell)
            if index == 0:
                print('Erreur, fin de fichier rencontrée')
            elif index == 1:
                print(f'Erreur, délai dépassé pour la commande {cmde}')
        child.logfile.write('\n')
        child.logfile.close()
        child.close()

class RunSBCCommands():
    def __init__(self, argv):
        self.argv = argv
        self.progname = (self.argv[0].split(r'/'))[-1] # extract script name from sys.argv
        self.threads = list() # to store threads list
        self.threadSize = 3 # number of simultaneous threads
        self.runOn = 3  # store which cluster's node to run commands on,
                        # default is standby (3), 0 for both nodes and 2 for active node
        self.cmdes = [  # default commands to run
            "ssh -l <user> <ip>",
            "show health",
            "show version"]
        self.log = False
        self.delay = 30
        self.apSysRedundancy = ".1.3.6.1.4.1.9148.3.2.1.1.4.0" # OSBC status OID
        self.status = ("both", "init", "active", "standby", "out of service") # list of OSBC status
        self.exec = list() # store list of nodes to run the commands on
        self.searchin = list() # store searchin BBC_fields for BBC parsing
        self.searchout = [BBC_field.NAME, BBC_field.IP] # store BBC_fields to display
        self.METAs = { # META words to facilitate search
            'T3G': {
                'regex': (r'(PV\w{3}[1237][65])', self.searchin, self.searchout),
                'doc': '- T3G: all SBC in T3G production network'},
            'T3G DROM': {
                'regex': (r'(PV(CAY7|LAM7|MAY7|REU7))', self.searchin, self.searchout),
                'doc': '- T3G DROM: same as T3G but only for DROM locations'},
            'T3G METRO': {
                'regex': (r'(PV(BAY7|BOR7|CAE7|CLE7|DIJ7|GRE7|IDF1|IDF2|IDF3|LIL76|LYO7|MAR7|MON7|NAN7|ORL7|POI7|REI7|REN76|ROU7|STR7|TOU7))', self.searchin, self.searchout),
                'doc': '- T3G METRO: same as T3G but without DROM locations'},
            'T3G Q': {
                'regex': (r'(PVTST06)', self.searchin, self.searchout),
                'doc': '- T3G Q: only SBC in qualification platform'},
            'T3G PP': {
                'regex': (r'PVREN8', self.searchin, self.searchout),
                'doc': '- T3G PP: only SBC in Pre-Production platform'},
            'NBI': {
                'regex': (r'(VOIPAcmeSD6300_ISBC)|(^SR(LIL|LYO|REI)\d{3}$)|(^SRREN60[34]$)', self.searchin, self.searchout),
                'doc': '- NBI : all SR/SD in NBI production network'},
            'NBI SR': {
                'regex': (r'(^SR(LIL|LYO|REI)\d{3}$)|(^SRREN60[34]$)', self.searchin, self.searchout),
                'doc': '- NBI SR: all SR in NBI production network'},
            'NBI SD': {
                'regex': (r'VOIPAcmeSD6300_ISBC', self.searchin, self.searchout),
                'doc': '- NBI SD: all SD in NBI production network'},
            'NBI G1': {
                'regex': (r'(PV(LIL6|LYO6|MAR6|TOU6))', self.searchin, self.searchout),
                'doc': '- NBI G1: all SD from group 1 in NBI production network'},
            'NBI G2': {
                'regex': (r'(PV(CAE6|DIJ6|GRE6|ROU6))', self.searchin, self.searchout),
                'doc': '- NBI G2: all SD from group 2 in NBI production network'},
            'NBI G3': {
                'regex': (r'(PV(BOR6|IDF61|IDF63|REI6))', self.searchin, self.searchout),
                'doc': '- NBI G3: all SD from group 3 in NBI production network'},
            'NBI G4': {
                'regex': (r'(PV(BAY6|IDF62|ORL6|POI6))', self.searchin, self.searchout),
                'doc': '- NBI G4: all SD from group 4 in NBI production network'},
            'NBI DROM': {
                'regex': (r'(PV(LAM|REU)60)', self.searchin, self.searchout),
                'doc': '- NBI DROM: all SD from DROM location in NBI production network'},
            'NBI Q': {
                'regex': (r'((SR|PV)TST02)[12]$', self.searchin, self.searchout),
                'doc': '- NBI Q: all SR/SD in NBI qualification platform'},
            'NBI PP': {
                'regex': (r'(SRREN60[12]$|PVREN60)', self.searchin, self.searchout),
                'doc': '- NBI PP: all SR/SD in NBI Pre-Production platform'}}
        self.SNMPv3UserAuth = 'muztc-v3-ro' # SNMPv3 stuff
        self.SNMPv3UserPriv = 'muztc-v3-chiffrement'
        self.SNMPv3PassAuth = passepass.getpass(self.SNMPv3UserAuth, 'getpass.priv.ztc.rbci.orange.net')
        self.SNMPv3PassPriv = passepass.getpass(self.SNMPv3UserPriv, 'getpass.priv.ztc.rbci.orange.net')

        eqpt_params_list = self.ParseParams() # parse sys.argv then return a approximate list of 'elected' nodes
        search_BBC_list = self.GenBBCSearchRequest(eqpt_params_list) # take the approximate list and returns a hostnames list
        p = BBC_Parser()
        result_BBC_list = list() # store detailed list (NAME and IP) of nodes
        for i in search_BBC_list: # create this detailed list of nodes
            result_BBC_list.append(p.get(*i))

        nodes = [(node['NAME'], node['IP']) for index in result_BBC_list for node in index] # Create nodes list with only wanted params
        # print(json.dumps(nodes, indent=4))
        self.StartThreads(nodes) # then start threads and that's all folks !!!

    def ParseParams(self):
        if len(self.argv) <= 1: # needs 1 arg at less
            self.Usage(self.progname, err='missing arguments')

        flags = (r'-h', r'-e', r'-f', r'-n', r'-r', r'-c', r'-l', r'-d') # list of possible flags for this script
        for (i, param) in enumerate(self.argv[1:]): # find bad flags in params then exit
            if not param in flags and not self.argv[i+1-1] in flags:
                self.Usage(self.argv[0], err='Bad argument(s)')

        if r'-h' in self.argv[1:]: # find help flag then exit
            self.Usage(self.argv[0])

        eqpt_params_list = list()
        for (i, param) in enumerate(self.argv[1:]): # parse params
            if self.argv[i+1] == r'-e': # split and store eqpt list
                eqpt_params_list = list(map(str.strip, self.argv[i+2].split(';')))
            elif self.argv[i+1] == r'-f': # read and parse file with eqpt list in then store it
                if Path(self.argv[i+2]).is_file():
                    with open(self.argv[i+2]) as f:
                        lines = f.read().splitlines()
                        f.close()
                for line in lines:
                    eqpt_params_list.append(line)
            elif self.argv[i+1] == r'-n': # get number of simultaneous threads
                if self.argv[i+2].isdigit():
                    self.threadSize = int(self.argv[i+2])
                else:
                    self.Usage(self.progname, err='-n must be followed by a numeric value')
            elif self.argv[i+1] == r'-r': # get which node to run on the script
                if self.argv[i+2].lower() in ("both", "active", "standby"):
                    self.runOn = self.argv[i+2].lower()
                    if self.argv[i+2].lower() == "both":
                        self.runOn = 0
                    elif self.argv[i+2].lower() == "active":
                        self.runOn = 2
                    elif self.argv[i+2].lower() == "standby":
                        self.runOn = 3
                else:
                    self.Usage(self.progname, err='-r must be followed by \'both\', \'active\' or \'standby\'')
            elif self.argv[i+1] == r'-c': # read and store commands file
                cmdesFile = self.argv[i+2]
                if Path(cmdesFile).is_file():
                    with open(cmdesFile) as f:
                        self.cmdes = f.read().splitlines()
                        f.close()
            elif self.argv[i+1] == r'-l': # to display logs on console /!\ only for one eqpt, won't work with a list
                self.log = True
            elif self.argv[i+1] == r'-d': # get timeout delay
                if self.argv[i+2].isdigit():
                    self.delay = int(self.argv[i+2])
                else:
                    self.Usage(self.progname, err='-d must be followed by a numeric value')
        return eqpt_params_list

    def GenBBCSearchRequest(self, eqpt_params_list):
        search_list = list()
        for i in eqpt_params_list: # loop to parse for META word and single eqpt in params
            if i in self.METAs.keys():
                # print(f'i="{i}"')
                search_list.append(self.METAs[i]['regex'])
            else:
                # print(f'{i}')
                node = re.match(r'((PV|SR)\w{3}\d{0,3})$', i, re.I)
                if node:
                    sr_match = re.search(r'(SR\w{3}\d{0,3})', node.group(1), re.I)
                    if sr_match: # if node is a session router, create REGEX for wancom0 only (don't display ILOM's IP)
                        search_list.append((sr_match.group(1)+'(?!.*_ILOM)', self.searchin, self.searchout))
                    else: # other eqpt have no ILOM, so the REGEX is simpler
                        search_list.append((i, [BBC_field.NAME], self.searchout))
                else: # the name provided if not one that matches SR or SD ones
                    print(f'{i} is not known yet')
        return search_list

    def StartThreads(self, nodesList):
        for node in nodesList:
            # print(f'cluster={node}, {node[0]}, {node[1]} ')
            # print(f'SNMPv3Get on {node[0]}:{node[1]}')
            result = int(self.SNMPv3Get(node[1], # get node's status
                self.SNMPv3UserAuth, self.SNMPv3PassAuth, self.SNMPv3PassPriv,
                usmHMAC192SHA256AuthProtocol, usmAesCfb128Protocol,
                self.apSysRedundancy))
            if result == self.runOn: # if status is right, then append node to exec list
                self.exec.append({node[0]:node[1]})
            elif self.runOn == 0 and (result in (2, 3)): # or if should run on both nodes with right status
                self.exec.append({node[0]:node[1]})      # append to exec list
        # print(f'self.exec={json.dumps(self.exec, indent=4)}')

        miniThreadsLists = [self.exec[i[0]:i[0]+self.threadSize] for i in enumerate(self.exec) if i[0]%self.threadSize==0]
        # create list of threads regarding simultaneous number of threads wanted
        # print(f'miniThreadsList={json.dumps(miniThreadsLists, indent=4)}')

        for nodes in miniThreadsLists: # for each group of threads
            for eachThread in nodes: 
                for node in eachThread.keys(): # create a thread for each node
                    self.threads.append(MyThread(node, eachThread[node], self.cmdes, self.delay, self.log))
            for t in self.threads: # then start them
                t.start()
            for t in self.threads: # then append them to the thread managing list
                t.join()
            self.threads.clear() # at the end of threads, clear them from managing list
        #     print(f'Nettoyage des threads, {self.threadSize} exécutés')
        #     print()
        # print('Fin d\'exécution du script')

    def SNMPv3Get (self, IP, user, auth_password, priv_password, auth_protocol, priv_protocol, OID):
        iterator = getCmd(
            SnmpEngine(),
            UsmUserData(user, auth_password, priv_password,
                        authProtocol = auth_protocol,
                        privProtocol=priv_protocol),
            UdpTransportTarget((IP, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(OID))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication:
            print(errorIndication)
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            for varBind in varBinds:
                # print(' = '.join([x.prettyPrint() for x in varBind]))
                return varBind[1]

    def Usage(self, progname, selfexit='', err=''):
        if err:
            print(f'Error : {err}\n')
        print(f'Usage : {progname} [-h] (-e "<eqpts list>"|-f <file>) [-c <file>] [-n <integer>] [-r <active|standby|both>] [-l]')
        helpstr =  ['   -h                  This help',
                    '   -e "E1;E2;...;En"   Equipments list \';\' separated',
                    '   -f file             File containing equipments list, one by line',
                    '   -c file             Commands to run, default is \'ssh\' to node then',
                    '                           do \'show health\' and \'show version\'',
                    '   -n int              Number of threads, default is 3',
                    '   -r str              On which node to run commands, default is standby node',
                    '   -l                  Display logs instead of writing them into a file',
                    '                           (works with only one node), default logs to file',
                    '   -d int              Number of seconds to wait before timeout',
                    'Both \'-e\' and \'-f\' can be used in the same command line.',
                    '',
                    'Equipment list can also contain one or many of those META words :'
                    ]
        last_helpstr = [
                    'The list of words must be surrounded by quotes to avoid any misinterpretation',
                    'of space and \';\' characters.',
                    ''
                    ]

        for i in self.METAs:
            helpstr.append('    '+self.METAs[i]['doc'])
        for i in last_helpstr:
            helpstr.append(i)

        for msg in helpstr:
            print(msg)
        sys.exit(selfexit)

if __name__ == "__main__":
    RunSBCCommands(sys.argv)
    # RunSBCCommands(('pouet', '-e', ' pvlil601 ;T3G DROM ', '-c', 'Cmdes.ssh.list', '-r', 'both', '-n', '6', '-f', 'Liste.SBC.txt'))
    # RunSBCCommands(('pouet', '-e', 'srrei601', '-r', 'both'))
