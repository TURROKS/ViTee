#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "MIT"
__version__ = "1.3.0"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

from time import sleep
import sys

import iocextract
from termcolor import colored

from scripts.constants import LOGO
from scripts.constants import DOMAIN_REGEX
from scripts.helpers import calculate_wait_time
from scripts.helpers import create_ip_report
from scripts.helpers import create_hash_report
from scripts.helpers import create_domain_report
from scripts.helpers import create_url_report

# Global Variables
IPs = []
Hashes = []
URLs = []
Files = []
Emails = []
Domains = []
Total_IOCs = 0


def virustotal_analyzer(api_key, api_type, inf, wait_time, api_version):

    # Variables
    ip_file_cnt = 0
    dom_file_cnt = 0
    url_file_cnt = 0
    hash_file_cnt = 0

    sys.stdout.write(colored(LOGO, 'green') + '\n')
    sys.stdout.write(f'You have selected the {api_version} API version'+'\n\n')
    sys.stdout.write('### Checking Unique IOCs ###' + '\n')

    with open(inf, 'r') as file:
        # Check the input file for IOCs
        for line in file:

            for ip in iocextract.extract_ipv4s(line, refang=True):
                if ip not in IPs:
                    IPs.append(ip)
                    sys.stdout.write(ip+'\n')
                else:
                    pass

            for dom in iocextract.extract_custom_iocs(line, DOMAIN_REGEX):
                if dom not in Domains:
                    Domains.append(dom)
                    sys.stdout.write(dom + '\n')
                else:
                    pass

            for url in iocextract.extract_urls(line, refang=True):
                if url not in URLs:
                    URLs.append(url)
                    sys.stdout.write(url + '\n')
                else:
                    pass

            for hash_check in iocextract.extract_hashes(line):
                if hash_check not in Hashes:
                    Hashes.append(hash_check)
                    sys.stdout.write(hash_check + '\n')
                else:
                    pass

        sys.stdout.write('\n')
        calculate_wait_time(api_type, IPs, Hashes, URLs, Files, Emails, Domains)
        sys.stdout.write('\n')
        sys.stdout.write('VT Detection Ratio Total_Samples/Detection Count'+'\n')

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
