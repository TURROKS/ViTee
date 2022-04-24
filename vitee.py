#!/usr/bin python3

__author__ = "Mario Rojas"
__license__ = "MIT"
__version__ = "1.2.0"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import sys
from time import sleep
import argparse
import configparser
import iocextract
from termcolor import colored
from colorama import init
import scripts.helpers as funcs
import scripts.constants as const

init()
# ConfigParser Setup
config = configparser.ConfigParser()
config.read('config.ini')
key = config.get('access', 'key')

# ArgParser Setup
parser = argparse.ArgumentParser(description="This Tool leverages Virus Total's API for reporting",
                                 epilog='Enjoy the tool')
parser.add_argument('-i', '--infile', type=str, help='Input File')
parser.add_argument('-o', '--outfile', type=str, help='Output File')
parser.add_argument('-a', '--api', type=str, default=key, help='Manually Enter API')
parser.add_argument('-m', '--membership', type=int, default=1, choices=[1, 2], help='API Type 1=Free(Default), 2=Paid')
parser.add_argument('-u', '--update', help='Update API')

# Global Arguments
args = parser.parse_args()
IPs = []
Hashes = []
URLs = []
Files = []
Emails = []
Domains = []
Total_IOCs = 0


def update_key(api_key):
    """This Function Updates the API"""
    config.set('access', 'key', api_key)
    with open('config.ini', 'w') as configFile:
        config.write(configFile)
    sys.stdout.write('Your API {} has been updated'.format(args.update))
    sys.stdout.write('\n')


def worker(api_k, inf, api_type):
    """Main Function"""
    if api_type == 1:

        ip_file_cnt = 0
        dom_file_cnt = 0
        url_file_cnt = 0
        hash_file_cnt = 0
        dom_rex = ['^([a-z0-9]{1,61}.[a-z]{2,})$']
        sys.stdout.write(colored(const.LOGO, 'green'))
        sys.stdout.write('\n')
        sys.stdout.write('You have selected the Free API version')
        sys.stdout.write('\n')
        sys.stdout.write('\n')
        sys.stdout.write('### Checking Unique IOCs ###')
        sys.stdout.write('\n')
        # print('your api is {}'.format(api_k))
        with open(inf, 'r') as file:
            # Check the input file for IOCs
            for line in file:

                for ip in iocextract.extract_ipv4s(line, refang=True):
                    if ip not in IPs:
                        IPs.append(ip)
                        sys.stdout.write(ip)
                        sys.stdout.write('\n')
                    else:
                        pass

                for dom in iocextract.extract_custom_iocs(line, dom_rex):
                    if dom not in Domains:
                        Domains.append(dom)
                        sys.stdout.write(dom)
                        sys.stdout.write('\n')
                    else:
                        pass

                for url in iocextract.extract_urls(line, refang=True):
                    if url not in URLs:
                        URLs.append(url)
                        sys.stdout.write(url)
                        sys.stdout.write('\n')
                    else:
                        pass

                for hash_check in iocextract.extract_hashes(line):
                    if hash_check not in Hashes:
                        Hashes.append(hash_check)
                        sys.stdout.write(hash_check)
                        sys.stdout.write('\n')
                    else:
                        pass

            sys.stdout.write('\n')
            funcs.wait_time(api_type, IPs, Hashes, URLs, Files, Emails, Domains)
            sys.stdout.write('\n')
            sys.stdout.write('VT Detection Ratio Total_Samples/Detection Count')
            sys.stdout.write('\n')

            # Get the IPs from the list to be queried
            for ip in IPs:
                funcs.ip_report(api_k, ip_file_cnt, ip)
                ip_file_cnt += 1
                sleep(15)

            for dom in Domains:
                funcs.domain_report(api_k, dom_file_cnt, dom)
                dom_file_cnt += 1
                sleep(15)

            for url in URLs:
                funcs.url_report(api_k, url_file_cnt, url)
                url_file_cnt += 1
                sleep(15)

            for hash_check in Hashes:
                funcs.hash_report(api_k, hash_file_cnt, hash_check)
                hash_file_cnt += 1
                sleep(15)

    elif api_type == 2:

        ip_file_cnt = 0
        dom_file_cnt = 0
        url_file_cnt = 0
        hash_file_cnt = 0
        dom_rex = ['^([a-z0-9]{1,61}.[a-z]{2,})$']
        sys.stdout.write(colored(const.LOGO, 'green'))
        sys.stdout.write('\n')
        sys.stdout.write('### You have selected the Paid API version ###')
        sys.stdout.write('\n\n')

        with open(inf, 'r') as file:
            for line in file:
                for ip in iocextract.extract_ipv4s(line, refang=True):
                    if ip not in IPs:
                        IPs.append(ip)
                        sys.stdout.write(ip)
                        sys.stdout.write('\n')
                    else:
                        pass

                for dom in iocextract.extract_custom_iocs(line, dom_rex):
                    if dom not in Domains:
                        Domains.append(dom)
                        sys.stdout.write(dom)
                        sys.stdout.write('\n')
                    else:
                        pass

                for url in iocextract.extract_urls(line, refang=True):
                    if url not in URLs:
                        URLs.append(url)
                        sys.stdout.write(url)
                        sys.stdout.write('\n')
                    else:
                        pass

                for hash_check in iocextract.extract_hashes(line):
                    if hash_check not in Hashes:
                        Hashes.append(hash_check)
                        sys.stdout.write(hash_check)
                        sys.stdout.write('\n')
                    else:
                        pass

            sys.stdout.write('\n')
            funcs.wait_time(api_type, IPs, Hashes, URLs, Files, Emails, Domains)
            sys.stdout.write('\n')
            sys.stdout.write('VT Detection Ratio Total_Samples/Detection Count')
            sys.stdout.write('\n')

            # Get the IPs from the list to be queried
            for ip in IPs:
                funcs.ip_report(api_k, ip_file_cnt, ip)
                ip_file_cnt += 1
                sleep(1)

            for dom in Domains:
                funcs.domain_report(api_k, dom_file_cnt, dom)
                dom_file_cnt += 1
                sleep(1)

            for url in URLs:
                funcs.url_report(api_k, url_file_cnt, url)
                url_file_cnt += 1
                sleep(1)

            for hash_check in Hashes:
                funcs.hash_report(api_k, hash_file_cnt, hash_check)
                hash_file_cnt += 1
                sleep(1)
    else:
        sys.stdout.write('Invalid Membership Type\nAvailable options are:\n\t1=Free\n\t2=Paid')
        sys.stdout.write('\n')


def main():
    """Check if user wants to update API"""
    if args.update:
        update_key(args.update)
    # Check if a valid API has been provided
    elif args.api:
        # Check that the user has provided both input and output files
        if args.infile and args.outfile:
            worker(args.api, args.infile, args.membership)
            funcs.comb_files(args.outfile)
            funcs.clean_dir()
        else:
            sys.stdout.write('Missing Parameters')
            sys.stdout.write('\n')
    else:
        sys.stdout.write(colored('No API found in conf', 'red'))
        sys.stdout.write('\n')


if __name__ == '__main__':
    main()
