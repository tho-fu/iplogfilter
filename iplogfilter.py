#!/usr/bin/env python3
# -*- coding: utf-8 -*-

version = "0.12"

__author__ = "ThoFu"
__copyright__ = "Copyright 2021, ThoFu"
__credits__ = "ThoFu"
__license__ = "GPLv2"
__version__ = version
__maintainer__ = "ThoFu"

import re
import sys
import ipaddress
import os
import argparse

############# Config Variables #############
iplist = ['192.168.1.0/24','10.10.10.0/24']
############# Config Variables #############

class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m' # yellow
    FAIL = '\033[91m'    # red
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def checklogfile(logfilename):
    checkpath = os.path.isfile(logfilename)
    checkread = os.access(logfilename, os.R_OK)
    if checkpath is not False and checkread is not False:
        lfresult = True
    else:
        lfresult = False
    return lfresult

def replaceresults(stringdata):
    stringdata = str(stringdata)
    replaces = {' ': '_',
                ',': '',
                '[\']': '\']',
                '[\'[': '',
                ']\']': '',
                '[\'': '',
                '\']': ''}

    for key, value in replaces.items():
    
        stringdata = stringdata.replace(key, value)

    return stringdata

my_parser = argparse.ArgumentParser(
    description='Search for most wanted IP-Ranges in your logfiles',
    add_help=True,
    formatter_class=argparse.RawTextHelpFormatter,
    epilog="Example of usage: " + sys.argv[0] + " -t 1 logfile\n ",)

my_parser.add_argument('-v', '--version', action='version', version='%(prog)s {version}'.format(version=__version__))
my_parser.add_argument('-t', '--filetype', type=int, metavar='', required=True, help='input filetype - 1 = Fail2Ban - 2 = AuthLog')

my_parser.add_argument('logfile', type=str, help='logfile name and path')

args = my_parser.parse_args()

if args.filetype and args.logfile:

    if checklogfile(args.logfile) is not False:

        lst = []

        if args.filetype == 1:

            with open(args.logfile) as fh:
                fstring = fh.readlines()

            fh.close()

            for line in fstring:
        
                ippattern = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',line)
                time = re.findall(r'(\d{4}\-\d{2}\-\d{2} \d{2}\:\d{2}\:\d{2}\,{1})',line)
                descr = re.findall(r'(\[{1}[\w\-]{5,}\]{1})',line)

                if ippattern is not None and 'Found ' in line:
                    for match in ippattern:
                        for val in iplist:
                            if ipaddress.ip_address(match) in ipaddress.ip_network(val):
                                result = [descr[0], (time[0]).rstrip((time[0])[-1]), ippattern[0]]
                                lst.append(result)

            if not lst:
                print("No result")
            else:
                lst.sort(reverse=False)
                print("\n" + bcolors.OKGREEN + bcolors.UNDERLINE + "Result:" + bcolors.ENDC + "\n")
                print ("{:<30} {:<30} {:<25}".format('Description','Time','IP'))
                for v in lst:
                    ipdescr, iptime, ipip = v
                    print ("{:<30} {:<30} {:<25}".format( ipdescr, iptime, ipip))
                print("\n")

        elif args.filetype == 2:
        
            with open(args.logfile) as fh:
                fstring = fh.readlines()

            fh.close()

            for line in fstring:
        
                ippattern = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',line)
                time = re.findall(r'([a-zA-Z]{3} \d{2} \d{2}\:\d{2}\:\d{2})',line)
                descr = re.findall(r'([\w\-]{3,}\[{1})',line)

                if ippattern is not None and ('Accepted ' or 'Failed ') in line:
                    for match in ippattern:
                        for val in iplist:
                            if ipaddress.ip_address(match) in ipaddress.ip_network(val):
                                result = [(descr[0]).rstrip((descr[0])[-1]), time[0], ippattern[0]]
                                lst.append(result)

            if not lst:
                print("No result")
            else:
                lst.sort(reverse=False)
                print("\n" + bcolors.OKGREEN + bcolors.UNDERLINE + "Result:" + bcolors.ENDC + "\n")
                print ("{:<30} {:<30} {:<25}".format('Description','Time','IP'))
                for v in lst:
                    ipdescr, iptime, ipip = v
                    print ("{:<30} {:<30} {:<25}".format( ipdescr, iptime, ipip))
                print("\n")

        else:
            print ("Bad Filetype")
            raise SystemExit()

    else:
        print(bcolors.FAIL + "Logfile is not found or accessible" + bcolors.ENDC)
        raise SystemExit()