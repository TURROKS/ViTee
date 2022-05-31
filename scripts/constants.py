# Here are the variables that do not change during execution

__author__ = "Mario Rojas"
__license__ = "MIT"
__version__ = "1.2.1"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

DOMAIN_REGEX = ['^([a-z0-9]{1,61}.[a-z]{2,})$']
HEADERS = ['Type',
           'Field',
           'IOC',
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
LOGO = """
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
                                                          BY TURROKS"""
VT_DOMAIN_URL = 'https://www.virustotal.com/vtapi/v2/domain/report'
VT_HASH_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VT_IP_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
VT_URL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
