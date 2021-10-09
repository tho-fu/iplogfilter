#!/usr/bin/env python3
# -*- coding: utf-8 -*-

version = "0.13"

__author__ = "ThoFu"
__copyright__ = "Copyright 2021, ThoFu"
__credits__ = "ThoFu"
__license__ = "GPLv2"
__version__ = version
__maintainer__ = "ThoFu"
__website__ = "https://github.com/tho-fu/iplogfilter"

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

def removefl(data):
    data = data.rstrip(data[-1])
    data = data.lstrip(",")

    return data

def removeflif(dataif):
    dataif = dataif.rstrip(",match")
    dataif = dataif.lstrip(",")

    return dataif

my_parser = argparse.ArgumentParser(
    description='Search for most wanted IP-Ranges in your logfiles',
    add_help=True,
    formatter_class=argparse.RawTextHelpFormatter,
    epilog="Example of usage: " + sys.argv[0] + " -t 1 logfile\n ",)

my_parser.add_argument('-v', '--version', action='version', version='%(prog)s {version}'.format(version=__version__))
my_parser.add_argument('-t', '--filetype', type=int, metavar='', required=True, help='input filetype - 1 = Fail2Ban - 2 = AuthLog - 3 = OPNSense')

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
                print ("{:<30} {:<26} {:<20}".format('Description','Time','IP'))
                for v in lst:
                    ipdescr, iptime, ipip = v
                    print ("{:<30} {:<26} {:<20}".format( ipdescr, iptime, ipip))
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
                print ("{:<30} {:<26} {:<20}".format('Description','Time','IP'))
                for v in lst:
                    ipdescr, iptime, ipip = v
                    print ("{:<30} {:<26} {:<20}".format( ipdescr, iptime, ipip))
                print("\n")

        elif args.filetype == 3:
        
            with open(args.logfile) as fh:
                fstring = fh.readlines()

            fh.close()

            for line in fstring:
        
                ipsrcpattern = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|$)',line)[0]
                ipdstpattern = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|$)',line)[1]
                inorout = re.findall(r'(,in,|,out,)',line)
                passorblock = re.findall(r'(,pass,|,block,)',line)
                interface = re.findall(r'(,igb.*,match|$])',line)
                time = re.findall(r'(\d{4}\-\d{2}\-\d{2}T\d{2}\:\d{2}\:\d{2})',line)
                descr = re.findall(r'([\w\-]{3,}\[{1})',line)
                getports = re.findall(r'((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\,){2}\d{1,5}\,\d{1,5}|$)',line)[0]

                try:
                    getallports = getports.split(",")
                    srcport = getallports[2]
                    dstport = getallports[3]
                except:
                    print(bcolors.FAIL + "Wrong type of Logfile ?!" + bcolors.ENDC)

                if ipsrcpattern and ipdstpattern and inorout and passorblock and interface and time and descr and srcport and dstport is not None:
                    for val in iplist:

                        if ipaddress.ip_address(ipsrcpattern) in ipaddress.ip_network(val):
                            result = [(descr[0]).rstrip((descr[0])[-1]), time[0], ipsrcpattern, ipdstpattern, removefl(inorout[0]), srcport, dstport, 
                                    removefl(passorblock[0]), removeflif(interface[0])]
                            lst.append(result)

            if not lst:
                print("No result")
            else:
                lst.sort(reverse=False)
                print("\n" + bcolors.OKGREEN + bcolors.UNDERLINE + "Result:" + bcolors.ENDC + "\n")
                print ("{:<15} {:<24} {:<20} {:<20} {:<10} {:<14} {:<14} {:<10} {:<18}".format('Description','Time','SourceIP','DestIP','Direction',
                    'SourcePort','DestPort','Action','Interface'))
                for v in lst:
                    ipdescr, iptime, ipsrcip, ipdstip, ipinorout, ipsrcport, ipdstport, ippassorblock, ipinterface = v
                    print ("{:<15} {:<24} {:<20} {:<20} {:<10} {:<14} {:<14} {:<10} {:<18}".format( ipdescr, iptime, ipsrcip, ipdstip, ipinorout, 
                        ipsrcport, ipdstport, ippassorblock, ipinterface))
                print("\n")

        else:
            print ("Bad Filetype")
            raise SystemExit()

    else:
        print(bcolors.FAIL + "Logfile is not found or accessible" + bcolors.ENDC)
        raise SystemExit()