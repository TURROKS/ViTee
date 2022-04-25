#!/usr/bin python3
# This file contains the functions that create the reports

__author__ = "Mario Rojas"
__license__ = "MIT"
__version__ = "1.2.1"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import glob
import iocextract
import os
import pandas as pd
import requests
import scripts.constants as const
import sys
from termcolor import colored
from time import sleep


IPs = []
Hashes = []
URLs = []
Files = []
Emails = []
Domains = []
Total_IOCs = 0


def clean_temp_files():
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


def combine_files(report_file):
    """This Function combines all the temp files"""
    with open('temp_report.csv', 'w', encoding='UTF8') as report:

        for f in glob.glob('*_result_*.txt'):
            with open(f, 'r') as temp:
                for line in temp:
                    report.write(line)

    df = pd.read_csv('temp_report.csv', names=const.HEADERS, index_col=1)
    try:
        df_url_temp = df.loc[df['Type'] == 'URL']
        df_domain_temp = df.loc[df['Type'] == 'Domain']
        df_ip_temp = df.loc[df['Type'] == 'IP']
        df_hash_temp = df.loc[df['Type'] == 'Hash']

        df_hash = df_hash_temp.dropna(axis=1, how='all')
        df_url = df_url_temp.dropna(axis=1, how='all')
        df_ip = df_ip_temp.dropna(axis=1, how='all')
        df_domain = df_domain_temp.dropna(axis=1, how='all')

        with pd.ExcelWriter('{}.xlsx'.format(report_file)) as writer:
            df_domain.to_excel(writer, sheet_name='Domains')
            df_ip.to_excel(writer, sheet_name='IPs')
            df_url.to_excel(writer, sheet_name='URLs')
            df_hash.to_excel(writer, sheet_name='Hashes')

    except PermissionError:
        sys.stdout.write('Error Saving File, check if the file is being used!')


def create_ip_report(api_k, counter, ip):
    """This Function checks IPs against VirusTotal"""
    with open('IP_result_{}.txt'.format(counter), 'w') as dest:

        url = const.VT_IP_URL
        params = {'apikey': api_k, 'ip': ip}
        response = requests.get(url, params=params)
        data = response.json()
        max_num = []
        temp_ip = []

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
                try:
                    if data['detected_downloaded_samples'][item]['sha256'] not in temp_ip:
                        temp_ip.append(data['detected_communicating_samples'][item]['sha256'])
                        sys.stdout.write('({}/{}) IP {} communicating_sample {}'.format(
                            str(data['detected_communicating_samples'][item]['total']),
                            colored(str(data['detected_communicating_samples'][item]['positives']), 'red'), ip,
                            data['detected_communicating_samples'][item]['sha256']))
                        sys.stdout.write('\n')
                    else:
                        pass
                except (KeyError, IndexError):
                    pass
                try:
                    if data['detected_urls'][item]['url'] not in temp_ip:
                        temp_ip.append(data['detected_urls'][item]['url'])
                        sys.stdout.write('({}/{}) IP {} detected_url {}'.format(
                            str(data['detected_urls'][item]['total']),
                            colored(str(data['detected_urls'][item]['positives']), 'red'), ip,
                            data['detected_urls'][item]['url']))
                        sys.stdout.write('\n')
                    else:
                        pass
                except (KeyError, IndexError):
                    pass
        elif data['response_code'] == 0:
            sys.stdout.write('IP {} not found in Virus Total'.format(ip))
            sys.stdout.write('\n')

        else:
            pass


def create_domain_report(api_k, counter, domain):
    """This Function checks Domains against VirusTotal"""

    with open('Domain_result_{}.txt'.format(counter), 'w') as dest:

        url = const.VT_DOMAIN_URL
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
                except (KeyError, IndexError):
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
                except (KeyError, IndexError):
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
                except (KeyError, IndexError):
                    pass
        elif data['response_code'] == 0:
            sys.stdout.write('Domain {} not found in Virus Total'.format(domain))
            sys.stdout.write('\n')
        else:
            pass


def create_url_report(api_k, counter, url_check):
    """This Function checks Domains against VirusTotal"""

    with open('URL_result_{}.txt'.format(counter), 'w') as dest:

        url = const.VT_URL_URL
        params = {'apikey': api_k, 'resource': url_check}
        response = requests.get(url, params=params)
        data = response.json()
        url_filter = ['clean site', 'unrated site']
        temp_url = []

        if data['response_code'] == 1:

            for data_key in data['scans']:

                if data['scans'][data_key]['result'] not in url_filter:

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
                        dest.write('{},'.format(data_key))
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(str(data['scans'][data_key]['detected']) + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(data['scans'][data_key]['result'] + '\n')
                    except (KeyError, IndexError):
                        dest.write('' + '\n')
                    if url_check not in temp_url:
                        temp_url.append(url_check)
                        sys.stdout.write(
                            '({}/{}) URL {}'.format(str(data['total']), colored(str(data['positives']), 'red'),
                                                    url_check))
                        sys.stdout.write('\n')
                    else:
                        pass
                else:
                    if url_check not in temp_url:
                        if int(data['positives']) == 0:
                            temp_url.append(url_check)
                            sys.stdout.write(
                                '({}/{}) URL {}'.format(str(data['total']), colored(str(data['positives']), 'green'),
                                                        url_check))
                            sys.stdout.write('\n')
                        else:
                            pass
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


def create_hash_report(api_k, counter, hash_check):
    """This Function checks Domains against VirusTotal"""

    with open('Hash_result_{}.txt'.format(counter), 'w') as dest:

        url = const.VT_HASH_URL
        params = {'apikey': api_k, 'resource': hash_check}
        response = requests.get(url, params=params)
        data = response.json()
        temp_hash = []

        if data['response_code'] == 1:

            for data_key in data['scans']:

                if data['scans'][data_key]['detected']:

                    dest.write('Hash,')
                    dest.write(hash_check.strip() + ',')
                    dest.write(',,,,,,,,,,,,,,,,,,,,,,,,,,,,')
                    try:
                        dest.write('{},'.format(data_key))
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    try:
                        dest.write(str(data['scans'][data_key]['detected']) + ',')
                    except (KeyError, IndexError):
                        dest.write('' + ',')
                    dest.write(',')
                    try:
                        dest.write(str(data['scans'][data_key]['version'] + ','))
                    except (KeyError, IndexError, TypeError):
                        dest.write('' + ',')
                    try:
                        dest.write(data['scans'][data_key]['result'] + ',')
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
                    if hash_check not in temp_hash:
                        temp_hash.append(hash_check)
                        sys.stdout.write(
                            '({}/{}) Hash {}'.format(str(data['total']), colored(str(data['positives']), 'red'),
                                                     hash_check))
                        sys.stdout.write('\n')
                    else:
                        pass
                else:
                    if hash_check not in temp_hash:
                        if int(data['positives']) == 0:
                            temp_hash.append(hash_check)
                            sys.stdout.write(
                                '({}/{}) Hash {}'.format(str(data['total']),
                                                         colored(str(data['positives']), 'green'), hash_check))
                            sys.stdout.write('\n')
                        else:
                            pass
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


def calculate_wait_time(api_type, ip_list, hash_list, url_list, file_list, email_list, domain_list):

    if api_type == 1:

        count = (len(ip_list) + len(hash_list) + len(url_list) + len(file_list) + len(email_list) + len(domain_list))*15

        if count < 60:
            sys.stdout.write("Approximate wait time {} Seconds..".format(count))
            sys.stdout.write('\n')
        elif 60 <= count < 3600:
            mins = count/60
            sys.stdout.write("Approximate wait time {} Minutes..".format(mins))
            sys.stdout.write('\n')
        else:
            hours = (count/60)/60
            sys.stdout.write("Approximate wait time {} Hours..".format(hours))
            sys.stdout.write('\n')
    elif api_type == 2:

        count = (ip_list + hash_list + url_list + file_list + email_list + domain_list)

        if count < 60:
            sys.stdout.write("Approximate wait time {} Seconds..".format(count))
            sys.stdout.write('\n')
        elif 60 <= count < 3600:
            mins = count/60
            sys.stdout.write("Approximate wait time {} Minutes..".format(mins))
            sys.stdout.write('\n')
        else:
            hours = (count/60)/60
            sys.stdout.write("Approximate wait time {} Hours..".format(hours))
            sys.stdout.write('\n')
    else:
        sys.stdout.write("Wrong Selection")


def virustotal_analyzer(api_key, api_type, inf, wait_time, api_version):

    # Variables
    ip_file_cnt = 0
    dom_file_cnt = 0
    url_file_cnt = 0
    hash_file_cnt = 0

    sys.stdout.write(colored(const.LOGO, 'green'))
    sys.stdout.write('\n')
    sys.stdout.write('You have selected the {} API version'.format(api_version))
    sys.stdout.write('\n')
    sys.stdout.write('\n')
    sys.stdout.write('### Checking Unique IOCs ###')
    sys.stdout.write('\n')

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

            for dom in iocextract.extract_custom_iocs(line, const.DOMAIN_REGEX):
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
        calculate_wait_time(api_type, IPs, Hashes, URLs, Files, Emails, Domains)
        sys.stdout.write('\n')
        sys.stdout.write('VT Detection Ratio Total_Samples/Detection Count')
        sys.stdout.write('\n')

        # Get the IPs from the list to be queried
        for ip in IPs:
            create_ip_report(api_key, ip_file_cnt, ip)
            ip_file_cnt += 1
            sleep(wait_time)

        for dom in Domains:
            create_domain_report(api_key, dom_file_cnt, dom)
            dom_file_cnt += 1
            sleep(wait_time)

        for url in URLs:
            create_url_report(api_key, url_file_cnt, url)
            url_file_cnt += 1
            sleep(wait_time)

        for hash_check in Hashes:
            create_hash_report(api_key, hash_file_cnt, hash_check)
            hash_file_cnt += 1
            sleep(wait_time)


def request_handler(api_k, inf, api_type):

    if api_type == 1:
        virustotal_analyzer(api_k, api_type, inf, 15, 'Free')
    elif api_type == 2:
        virustotal_analyzer(api_k, api_type, inf, 1, 'Paid')
    else:
        sys.stdout.write('Invalid Membership Type\nAvailable options are:\n\t1=Free\n\t2=Paid')
        sys.stdout.write('\n')
