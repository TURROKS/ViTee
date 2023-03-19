#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "MIT"
__version__ = "1.2.1"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import sys

import argparse
from colorama import init
import configparser
from termcolor import colored

import scripts.helpers as funcs


init()
# ConfigParser Setup
config = configparser.ConfigParser()
config.read('config.ini')
key = config.get('access', 'key')

# ArgParser Setup
parser = argparse.ArgumentParser(description="Leverage Virus Total's Free or Paid APIs",
                                 epilog='Enjoy the tool')
parser.add_argument('-i', '--file', type=str, help='Provide a TXT file with the IOCs')
parser.add_argument('-s', '--string', type=str, help='Provide a comma separated string with the IOCs')
parser.add_argument('-o', '--output', type=str, help='Output filename - without Extension')
parser.add_argument('-a', '--api', type=str, default=key, help='Enter API key manually')
parser.add_argument('-m', '--membership', type=int, default=1, choices=[1, 2], help='API Type 1=Free(Default), 2=Paid')
parser.add_argument('-u', '--update', help='Update API')

# Global Arguments
args = parser.parse_args()


def update_key(api_key):
    """This Function Updates the API"""
    config.set('access', 'key', api_key)
    with open('config.ini', 'w') as configFile:
        config.write(configFile)
    sys.stdout.write('Your API {} has been updated'.format(args.update) +'\n')


if __name__ == '__main__':

    # Check if user wants to update API
    if args.update:
        update_key(args.update)
    # Check if a valid API has been provided
    elif args.api:
        # Check that the user has provided both input and output files
        if args.string:
            funcs.clean_temp_files()
            funcs.request_handler(api_key=args.api, string=args.string, api_type=args.membership)
            funcs.combine_files(args.output)
            funcs.clean_temp_files()
        elif args.file and args.output:
            funcs.clean_temp_files()
            funcs.request_handler(api_key=args.api, inputs_file=args.file, api_type=args.membership)
            funcs.combine_files(args.output)
            funcs.clean_temp_files()
        else:
            sys.stdout.write('Missing Parameters' + '\n')
    else:
        sys.stdout.write(colored('No API found in conf', 'red') + '\n')
