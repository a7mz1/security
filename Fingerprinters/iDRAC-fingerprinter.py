#! /usr/bin/python3
# -*- coding: utf-8 -*- 
r'''
	Copyright 2024 Photubias(c)
    Copyright (C) 2026 a7mz1

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.    
'''
import optparse
import requests
import json
import datetime
import os
from fake_useragent import UserAgent
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
requests.warnings.filterwarnings('ignore', category=DeprecationWarning) 

userAgentLib = UserAgent()
respTimeout = 10

reqHeaders = {'User-Agent' : userAgentLib.random, 'Content-Type': 'application/json'}
exportFileName = f'{datetime.datetime.now().strftime(r'%Y%m%d-%H%M%S')}-iDRACs.txt'
_lstToWrite = []

class CustomHTTPAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = requests.ssl.create_default_context()
        context.set_ciphers('ALL:@SECLEVEL=0')
        context.check_hostname = False
        context.minimum_version = requests.ssl.TLSVersion.SSLv3
        super().init_poolmanager(*args, **kwargs, ssl_context=context)

def fingerPrint(listArgs):
    (idracIp, boolVulns, boolExport) = listArgs
    global _lstToWrite
    def getPage(idracUrl):
        reqSession = requests.Session()
        reqSession.mount('https://', CustomHTTPAdapter())
        try:
            reqResponse = reqSession.get(idracUrl, verify=False, headers = reqHeaders, timeout = respTimeout)
            return reqResponse
        except:
            return None
        
    def getBMCInfo(reqResult):
        lstLines = reqResult.split('\n')
        for line in lstLines:
            if 'var BMC_INFO' in line: return line.split('"')[1]
        return ''

    def getFWViaRedfish(idracUrl):
        reqResponse = getPage(idracUrl + '/redfish/v1/Registries/ManagerAttributeRegistry/ManagerAttributeRegistry.v1_0_0.json')
        respJson = json.loads(reqResponse.text)
        return respJson['SupportedSystems'][0]['FirmwareVersion']

    idracUrl = 'https://' + idracIp
    # iDRAC 6 attempt (no unauthenticated Firmware Version here)
    reqResponse = getPage(idracUrl + '/login.html')
    if reqResponse and reqResponse.status_code == 200 and not 'idrac7' in reqResponse.text.lower():
        reqResult = reqResponse.text
        if 'idrac6' in reqResult.lower():
            idracFwVersion = 'Unknown'
            idracSystem = idracHostname = idracLicense = ''
            for line in reqResult.split('\n'):
                if 'var tmphostname' in line.lower(): 
                    idracHostname = line.split('"')[1].strip()
                elif 'integrated dell remote access controller 6' in line.lower(): 
                    idracLicense = line.split(r'- ')[1].split(r'<')[0]
            if boolExport:
                _lstToWrite.append(f'{idracIp};iDRAC6 {idracLicense};{idracSystem};{idracHostname};{idracFwVersion}\n')
            print(f'[+] {idracIp}: {idracHostname} (iDRAC6 {idracLicense}, Firmware {idracFwVersion})')
        return
    # iDRAC 7 & 8 attempt
    reqResponse = getPage(idracUrl + '/data?get=prodServerGen')
    if reqResponse and reqResponse.status_code == 200:
        try:
            if '12g' in reqResponse.text.lower():
                idracVersion = 'iDRAC7'
            else:
                idracVersion = 'iDRAC8'
            reqResponse = getPage(idracUrl + '/data?get=prodClassName')
            idracLicense = reqResponse.text.split(r'<prodClassName>')[1].split(r'</prodClassName>')[0]
            reqResponse = getPage(idracUrl + '/session?aimGetProp=hostname,gui_str_title_bar,OEMHostName,fwVersion,sysDesc')
            if reqResponse:
                respJson = json.loads(reqResponse.text)['aimGetProp']
                idracHostname = respJson['hostname']
                idracFwVersion = respJson['fwVersion']
                idracSystem = respJson['sysDesc']
                if boolExport:
                    _lstToWrite.append(f'{idracIp};{idracVersion} {idracLicense};{idracSystem};{idracHostname};{idracFwVersion}\n')
                print(f'[+] {idracIp}: {idracHostname} ({idracSystem}, {idracVersion} {idracLicense}, Firmware v{idracFwVersion})')
                if boolVulns:
                    getVulns(idracVersion, idracFwVersion, idracIp)
                return
        except:
            return

    # iDRAC 9 attempt
    reqResponse = getPage(idracUrl + '/restgui/locale/strings/locale_str_en.json')
    if reqResponse and reqResponse.status_code == 200:
        try:
            respJson = json.loads(reqResponse.text)
            if respJson['app_title'] == 'iDRAC9':
                reqResponse = getPage(idracUrl + '/restgui/js/services/resturi.js')
                reqResult = reqResponse.text
                idracEndpoint = getBMCInfo(reqResult)
                reqResponse = getPage(idracUrl + idracEndpoint)
                respJson = json.loads(reqResponse.text)['Attributes']
                idracHostname = respJson['iDRACName']
                if not 'FwVer' in respJson:
                    idracFwVersion = getFWViaRedfish(idracUrl)
                else:
                    idracFwVersion = respJson['FwVer']
                idracSystem = respJson['SystemModelName']
                idracLicense = respJson['License']
                if boolExport:
                    _lstToWrite.append(f'{idracIp};iDRAC9 {idracLicense};{idracSystem};{idracHostname};{idracFwVersion}\n')
                print('[+] {}: {} ({}, iDRAC9 {}, Firmware v{})'.format(idracIp, idracHostname, idracSystem, idracLicense, idracFwVersion))
                # if boolVulns: (no iDRAC9 vulnerabilities... yet.)
                #     getVulns(idracHostname, 'iDRAC9 {}'.format(idracLicense), idracFwVersion, idracIp, idracSystem)
                return
        except:
            return

def getIPs(cidr):
    def ip2bin(ip):
        b = ''
        inQuads = ip.split('.')
        outQuads = 4
        for q in inQuads:
            if q != '':
                b += dec2bin(int(q),8)
                outQuads -= 1
        while outQuads > 0:
            b += '00000000'
            outQuads -= 1
        return b

    def dec2bin(n,d=None):
        s = ''
        while n>0:
            if n&1:
                s = '1' + s
            else:
                s = '0' + s
            n >>= 1
        if d is not None:
            while len(s)<d: s = '0' + s
        if s == '':
            s = '0'
        return s

    def bin2ip(b):
        ip = ''
        for i in range(0,len(b),8):
            ip += str(int(b[i:i+8],2)) + '.'
        return ip[:-1]

    iplist=[]
    parts = cidr.split('/')
    if len(parts) == 1:
        iplist.append(parts[0])
        return iplist
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    if subnet == 32:
        iplist.append(bin2ip(baseIP))
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            iplist.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
    return iplist

def verifyCVE_2018_1207(idracIp):
    idracUrl = f'https://{idracIp}/cgi-bin/login?LD_DEBUG=files'
    reqNewHeaders = reqHeaders
    reqNewHeaders['Accept'] = ''
    reqSession = requests.Session()
    reqSession.mount('https://', CustomHTTPAdapter())
    reqResponse = reqSession.get(idracUrl, verify=False, headers = reqHeaders, timeout = respTimeout)
    if 'calling init: /lib/' in reqResponse.text:
        print(f'  [!!] {idracIp} is definitely vulnerable and can be exploited: {idracUrl}')
    return

def getIPsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstIPs = []
    for line in lstLines: # Line can be an IP or a CIDR
        for idracIp in getIPs(line):
            lstIPs.append(idracIp)
    return lstIPs

# Vulnerability checking based on version
def getVulns(idracVersion, idracFwVersion, idracIp):
    vulnMessage = '  [!] ' + idracIp + ' is potentially vulnerable to CVE-2018-1207, Code Injection Vulnerability (RCE)'
    boolCVE20181207 = False
    if '8' in idracVersion or '7' in idracVersion:
        # For some reason, /session returns versioning numbers differently.
        # For example, 2.52.52.52 is returned as 2.52.12.
        # In the original version of this script, this caused the script to flag an iDRAC
        # as vulnerable, even though the iDRAC was running version 2.52.52.52.
        major, minor, patch = map(int, idracFwVersion.split('.'))
        if (major, minor, patch) < (2, 52, 12):
            boolCVE20181207 = True
    if boolCVE20181207:
        print(vulnMessage)
        verifyCVE_2018_1207(idracIp)
    return

def writeFile(lstToWrite, exportFileName):
    with open(exportFileName,'w') as exportObject:
        for line in lstToWrite:
            exportObject.write(line+'\n')
        exportObject.close()
    print(f'[+] Created file {exportFileName} containing all {len(lstToWrite)} responsive IP addresses, feel free to run the IPMI scanner.')
    return

def main():
    fingerprinterUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs enumeration of iDRAC systems on a given subnet or IP\n'
              'When provided with the --scanvulns parameter it spits out critical vulns based on the Firmware version.')
    parser = optparse.OptionParser(usage = fingerprinterUsage)
    parser.add_option('--threads', '-t', metavar='INT', dest='threads', default = 64, help='Amount of threads. Default 64')
    parser.add_option('--scanvulns', '-s', dest='vulns', action='store_true', help='Check for common vulns.', default=False)
    parser.add_option('--export', '-e', dest='export', action='store_true', help='Create list of addresses running iDRAC. Default False', default=False)
    (options,args) = parser.parse_args()
    if not args or not len(args) == 1:
        addressInput = input('[?] Please enter the subnet or IP to scan [192.168.50.0/24] : ')
        if addressInput == '':
            addressInput = '192.168.50.0/24'
        lstIPs = getIPs(addressInput)
    else:
        if os.path.isfile(args[0]):
            print(f'[+] Parsing file {args[0]} for IP addresses/networks.')
            lstIPs = getIPsFromFile(args[0])
        else: 
            lstIPs = getIPs(args[0])
    tPool = ThreadPool(int(options.threads))
    print(f'[!] Scanning {len(lstIPs)} addresses using up to {options.threads} threads.')
    tPool.map(fingerPrint, zip(lstIPs, repeat(options.vulns), repeat(options.export)))
    if options.export:
        writeFile(_lstToWrite, exportFileName)
    return

if __name__ == '__main__':
    main()
