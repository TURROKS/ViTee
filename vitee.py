#!/usr/bin python3

__author__ = "Mario Rojas"
__license__ = "MIT"
__version__ = "1.2.1"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import sys
import argparse
import configparser
from termcolor import colored
from colorama import init
import scripts.helpers as funcs

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


def main():
    """Check if user wants to update API"""
    if args.update:
        update_key(args.update)
    # Check if a valid API has been provided
    elif args.api:
        # Check that the user has provided both input and output files
        if args.infile and args.outfile:
            funcs.request_handler(args.api, args.infile, args.membership)
            funcs.combine_files(args.outfile)
            funcs.clean_temp_files()
        else:
            sys.stdout.write('Missing Parameters')
            sys.stdout.write('\n')
    else:
        sys.stdout.write(colored('No API found in conf', 'red'))
        sys.stdout.write('\n')


if __name__ == '__main__':
    main()
