import argparse
import configparser
from time import sleep
import requests
import iocextract
import os
import glob
import pandas as pd
import sys
from termcolor import colored, cprint
from colorama import init

init()
# ConfigParser Setup
config = configparser.ConfigParser()
config.read('config.ini')
key = config.get('access', 'key')

# ArgParser Setup
parser = argparse.ArgumentParser(description="This Tool leverages Virus Total's API for reporting", epilog='Enjoy the tool')
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


def clean_dir():
    """This Function removes all temp files created for the reports"""
    for f in glob.glob('*_result_*.txt'):

        if f:
            os.remove(f)
        else:
            pass

    for f in glob.glob('temp_*'):

        if f:
            os.remove(f)
        else:
            pass


def comb_files(report_file):
    """This Function combines all the temp files"""
    with open('temp_report.csv', 'w', encoding='UTF8') as report:

        for f in glob.glob('*_result_*.txt'):
            with open(f, 'r') as temp:
                for line in temp:
                    report.write(line)

    header_list = ['Field',
                   'Type',
                   'IOC'
                   'Country',
                   'AS_Owner',
                   'Continent',
                   'resolutions_last_resolved',
                   'resolutions_host',
                   'resolutions_ip_address',
                   'detected_url',
                   'detected_urls_positives',
                   'detected_urls_total',
                   'detected_urls_scan_date',
                   'detected_communicating_samples_sha256',
                   'detected_communicating_samples_positives',
                   'detected_communicating_samples_total',
                   'detected_communicating_samples_scan_date',
                   'asn',
                   'network',
                   'subdomains',
                   'categories',
                   'dns_records_type',
                   'dns_records_value',
                   'detected_referrer_samples_date',
                   'detected_referrer_samples_positives',
                   'detected_referrer_samples_total',
                   'detected_referrer_samples_sha256',
                   'detected_downloaded_samples_date',
                   'detected_downloaded_samples_positives',
                   'detected_downloaded_samples_total',
                   'detected_downloaded_samples_sha256',
                   'Engine',
                   'Engine_detected',
                   'Engine_result',
                   'hash_scan_version',
                   'hash_scan_result',
                   'hash_sha1',
                   'hash_sha256',
                   'hash_md5',
                   'hash_total',
                   'hash_positives',
                   'hash_scan_date']

    df = pd.read_csv('temp_report.csv', names=header_list)
    try:
        df.to_csv('{}.csv'.format(report_file), index=False)
    except PermissionError:
        sys.stdout.write('Error Saving File, check if the file is being used!')


def ip_report(api_k, counter, ip):
    """This Function checks IPs against VirusTotal"""
    with open('IP_result_{}.txt'.format(counter), 'w') as dest:

        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': api_k, 'ip': ip}
        response = requests.get(url, params=params)
        data = response.json()
        max_num = []

        if data['response_code'] == 1:

            try:
                du_num = len(data['detected_urls'])
                max_num.append(du_num)
            except KeyError:
                du_num = 0
                max_num.append(du_num)
            try:
                dds_num = len(data['detected_communicating_samples'])
                max_num.append(dds_num)
            except KeyError:
                dds_num = 0
                max_num.append(dds_num)

            vals = (max(max_num) + 1)

            for item in range(0, vals):

                dest.write('IP,')
                dest.write(ip.strip() + ',')
                try:
                    dest.write(data['country'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write('"' + data['as_owner'] + '"' + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['continent'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['resolutions'][item]['last_resolved']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['resolutions'][item]['hostname']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                dest.write(',')
                try:
                    dest.write(data['detected_urls'][item]['url'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['detected_urls'][item]['positives']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['detected_urls'][item]['total']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['detected_urls'][item]['scan_date'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['detected_communicating_samples'][item]['sha256'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['detected_communicating_samples'][item]['positives']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['detected_communicating_samples'][item]['total']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['detected_communicating_samples'][item]['date'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['asn']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['network'] + '\n')
                except (KeyError, IndexError):
                    dest.write('' + '\n')

        elif data['response_code'] == 0:
            sys.stdout.write('IP {} not found in Virus Total'.format(ip))
            sys.stdout.write('\n')

        else:
            pass


def domain_report(api_k, counter, domain):
    """This Function checks Domains against VirusTotal"""

    with open('Domain_result_{}.txt'.format(counter), 'w') as dest:

        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey': api_k, 'domain': domain}
        response = requests.get(url, params=params)
        data = response.json()
        max_num = []
        temp_domain = []

        if data['response_code'] == 1:

            try:
                du_num = len(data['detected_urls'])
                max_num.append(du_num)
            except KeyError:
                du_num = 0
                max_num.append(du_num)
            try:
                dns_num = len(data['dns_records'])
                max_num.append(dns_num)
            except KeyError:
                dns_num = 0
                max_num.append(dns_num)
            try:
                subdns_num = len(data['subdomains'])
                max_num.append(subdns_num)
            except KeyError:
                subdns_num = 0
                max_num.append(subdns_num)
            try:
                res_num = len(data['resolutions'])
                max_num.append(res_num)
            except KeyError:
                res_num = 0
                max_num.append(res_num)
            try:
                drs_num = len(data['detected_referrer_samples'])
                max_num.append(drs_num)
            except KeyError:
                drs_num = 0
                max_num.append(drs_num)
            try:
                dds_num = len(data['detected_downloaded_samples'])
                max_num.append(dds_num)
            except KeyError:
                dds_num = 0
                max_num.append(dds_num)

            vals = (max(max_num) + 1)

            for item in range(0, vals):

                dest.write('Domain,')
                dest.write(domain.strip() + ',')
                dest.write(',,,')
                try:
                    dest.write(str(data['resolutions'][item]['last_resolved']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                dest.write(',')
                try:
                    dest.write(str(data['resolutions'][item]['ip_address']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['detected_urls'][item]['url'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['detected_urls'][item]['positives']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['detected_urls'][item]['total']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['detected_urls'][item]['scan_date'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                dest.write(',,,,,,')
                try:
                    dest.write(data['subdomains'][item] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['categories'][item] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['dns_records'][item]['type'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['dns_records'][item]['value'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['detected_referrer_samples'][item]['date'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['detected_referrer_samples'][item]['positives']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['detected_referrer_samples'][item]['total']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['detected_referrer_samples'][item]['sha256'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['detected_downloaded_samples'][item]['date'] + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['detected_downloaded_samples'][item]['positives']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(str(data['detected_downloaded_samples'][item]['total']) + ',')
                except (KeyError, IndexError):
                    dest.write('' + ',')
                try:
                    dest.write(data['detected_downloaded_samples'][item]['sha256'] + '\n')
                except (KeyError, IndexError):
                    dest.write('' + '\n')
                try:
                    if data['detected_downloaded_samples'][item]['sha256'] not in temp_domain:
                        temp_domain.append(data['detected_downloaded_samples'][item]['sha256'])
                        sys.stdout.write('({}/{}) Domain {} downloaded_sample {}'.format(
                            str(data['detected_downloaded_samples'][item]['total']),
                            colored(str(data['detected_downloaded_samples'][item]['positives']), 'red'), domain,
                            data['detected_downloaded_samples'][item]['sha256']))
                        sys.stdout.write('\n')
                    else:
                        pass
                except IndexError:
                    pass
                try:
                    if data['detected_referrer_samples'][item]['sha256'] not in temp_domain:
                        temp_domain.append(data['detected_referrer_samples'][item]['sha256'])
                        sys.stdout.write('({}/{}) Domain {} referrer_sample {}'.format(
                            str(data['detected_referrer_samples'][item]['total']),
                            colored(str(data['detected_referrer_samples'][item]['positives']), 'red'), domain,
                            data['detected_referrer_samples'][item]['sha256']))
                        sys.stdout.write('\n')
                    else:
                        pass
                except IndexError:
                    pass
                try:
                    if data['detected_urls'][item]['url'] not in temp_domain:
                        temp_domain.append(data['detected_urls'][item]['url'])
                        sys.stdout.write('({}/{}) Domain {} linked url {}'.format(
                            str(data['detected_urls'][item]['total']),
                            colored(str(data['detected_urls'][item]['positives']), 'red'), domain,
                            data['detected_urls'][item]['url']))
                        sys.stdout.write('\n')
                    else:
                        pass
                except IndexError:
                    pass
        elif data['response_code'] == 0:
            sys.stdout.write('Domain {} not found in Virus Total'.format(domain))
            sys.stdout.write('\n')
        else:
            pass


def url_report(api_k, counter, url_check):
    """This Function checks Domains against VirusTotal"""

    with open('URL_result_{}.txt'.format(counter), 'w') as dest:

        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': api_k, 'resource': url_check}
        response = requests.get(url, params=params)
        data = response.json()
        url_filter = ['clean site', 'unrated site']
        temp_url = []

        if data['response_code'] == 1:

            for key in data['scans']:

                if data['scans'][key]['result'] not in url_filter:

                    dest.write('URL,')
                    dest.write(url_check.strip() + ',')
                    dest.write(',,,,,,')
                    try:
                        dest.write(data['url'] + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(str(data['positives']) + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(str(data['total']) + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(data['scan_date'] + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    dest.write(',,,,,,,,,,,,,,,,,,')
                    try:
                        dest.write('{},'.format(key))
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(str(data['scans'][key]['detected']) + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(data['scans'][key]['result'] + '\n')
                    except (KeyError, IndexError):
                        dest.write('' + '\n')
                    if url_check in temp_url:
                        pass
                    else:
                        temp_url.append(url_check)
                        sys.stdout.write('({}/{}) URL {}'.format(str(data['total']), colored(str(data['positives']), 'red'), url_check))
                        sys.stdout.write('\n')
                else:
                    pass
        elif data['response_code'] == 0:
            if url_check in temp_url:
                pass
            else:
                temp_url.append(url_check)
                sys.stdout.write(colored('URL {} not found in Virus Total', 'green').format(url_check))
                sys.stdout.write('\n')
        else:
            pass


def hash_report(api_k, counter, hash_check):
    """This Function checks Domains against VirusTotal"""

    with open('Hash_result_{}.txt'.format(counter), 'w') as dest:

        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api_k, 'resource': hash_check}
        response = requests.get(url, params=params)
        data = response.json()
        temp_hash = []

        if data['response_code'] == 1:

            for key in data['scans']:

                if data['scans'][key]['detected']:

                    dest.write('Hash,')
                    dest.write(hash_check.strip() + ',')
                    dest.write(',,,,,,,,,,,,,,,,,,,,,,,,,,,,')
                    try:
                        dest.write('{},'.format(key))
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(str(data['scans'][key]['detected']) + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    dest.write(',')
                    try:
                        dest.write(str(data['scans'][key]['version'] + ','))
                    except (KeyError, IndexError, TypeError):
                        dest.write('' + ',')
                    try:
                        dest.write(data['scans'][key]['result'] + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(data['sha1'] + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(data['sha256'] + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(data['md5'] + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(str(data['total']) + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(str(data['positives']) + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(data['scan_date'] + '\n')
                    except (KeyError, IndexError):
                        dest.write('' + '\n')
                    if hash_check in temp_hash:
                        pass
                    else:
                        temp_hash.append(hash_check)
                        sys.stdout.write('({}/{}) Hash {}'.format(str(data['total']), colored(str(data['positives']), 'red'), hash_check))
                        sys.stdout.write('\n')
                else:
                    pass
        elif data['response_code'] == 0:
            if hash_check in temp_hash:
                pass
            else:
                temp_hash.append(hash_check)
                sys.stdout.write(colored('Hash {} not found in Virus Total', 'green').format(hash_check))
                sys.stdout.write('\n')
        else:
            pass


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

        ipFileCnt = 1
        domFileCnt = 0
        urlfilecnt = 0
        hashfilecnt = 0
        dom_rex = ['^([a-z0-9]{1,61}\.[a-z]{2,})$']
        sys.stdout.write(colored("""
                                              ___           ___     
      ___                                    /\__\         /\__\    
     /\  \        ___           ___         /:/ _/_       /:/ _/_   
     \:\  \      /\__\         /\__\       /:/ /\__\     /:/ /\__\  
      \:\  \    /:/__/        /:/  /      /:/ /:/ _/_   /:/ /:/ _/_ 
  ___  \:\__\  /::\  \       /:/__/      /:/_/:/ /\__\ /:/_/:/ /\__
 /\  \ |:|  |  \/\:\  \__   /::\  \      \:\/:/ /:/  / \:\/:/ /:/  /
 \:\  \|:|  |   ~~\:\/\__\ /:/\:\  \      \::/_/:/  /   \::/_/:/  / 
  \:\__|:|__|      \::/  / \/__\:\  \      \:\/:/  /     \:\/:/  /  
   \::::/__/       /:/  /       \:\__\      \::/  /       \::/  /   
    ~~~~           \/__/         \/__/       \/__/         \/__/    
    """, 'green'))
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
                        #sys.stdout.write('IP {} Already in List'.format(ip))
                        #sys.stdout.write('\n')

                for dom in iocextract.extract_custom_iocs(line, dom_rex):
                    if dom not in Domains:
                        Domains.append(dom)
                        sys.stdout.write(dom)
                        sys.stdout.write('\n')
                    else:
                        pass
                        #sys.stdout.write('Domain {} Already in List'.format(dom))
                        #sys.stdout.write('\n')

                for url in iocextract.extract_urls(line, refang=True):
                    if url not in URLs:
                        URLs.append(url)
                        sys.stdout.write(url)
                        sys.stdout.write('\n')
                    else:
                        pass
                        #sys.stdout.write('URL {} Already in List'.format(url))
                        #sys.stdout.write('\n')

                for hash_check in iocextract.extract_hashes(line):
                    if hash_check not in Hashes:
                        Hashes.append(hash_check)
                        sys.stdout.write(hash_check)
                        sys.stdout.write('\n')
                    else:
                        pass
                        #sys.stdout.write('Hash {} Already in List'.format(hash_check))
                        #sys.stdout.write('\n')
            sys.stdout.write('\n')
            sys.stdout.write('VT Detection Ratio Total_Samples/Detection Count')
            sys.stdout.write('\n')

            # Get the IPs from the list to be queried
            for ip in IPs:
                ip_report(api_k, ipFileCnt, ip)
                ipFileCnt += 1
                sleep(15)

            for dom in Domains:
                domain_report(api_k, domFileCnt, dom)
                domFileCnt += 1
                sleep(15)

            for url in URLs:
                url_report(api_k, urlfilecnt, url)
                urlfilecnt += 1
                sleep(15)

            for hash_check in Hashes:
                hash_report(api_k, hashfilecnt, hash_check)
                hashfilecnt += 1
                sleep(15)

    elif api_type == 2:
        sys.stdout.write('### You have selected the Paid API version ###')
        sys.stdout.write('\n\n')

        with open(inf, 'r') as file:
            for line in file:
                for ip in iocextract.extract_ipv4s(line, refang=True):
                    if ip not in IPs:
                        IPs.append(ip)
                        sys.stdout.write(ip)
                    else:
                        sys.stdout.write(ip + ' Already in List')
                        sys.stdout.write('\n')
                sleep(0)
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
            comb_files(args.outfile)
            clean_dir()
        else:
            sys.stdout.write('Missing Parameters')
            sys.stdout.write('\n')
    else:
        sys.stdout.write(colored('No API found in conf', 'red'))
        sys.stdout.write('\n')


if __name__ == '__main__':
    main()
