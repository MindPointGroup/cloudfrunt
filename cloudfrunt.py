#!/usr/bin/env python

import os
import sys
import time
import json
import socket
import urllib2
import argparse
import textwrap

# pip install netaddr
# pip install dnspython
# git clone https://github.com/darkoperator/dnsrecon.git

from netaddr import IPNetwork
from subprocess import call

__author__ = 'Matt Westfall'
__version__ = '1.0.0'
__email__ = 'disloops@gmail.com'

# parse the input file
def get_domains(input_file):

    with open(input_file, 'r') as f:
        domains = f.readlines()
    domains = [domain.strip() for domain in domains]
    return domains

# find more domains using dnsrecon
def get_dnsrecon(domains):

    # hotfix for dnsrecon (v0.8.12) to avoid user input
    with open('./dnsrecon/dnsrecon.py', 'r') as f:
      dnsrecon_data = f.read()
    dnsrecon_data = dnsrecon_data.replace('continue_brt = str(sys.stdin.readline()[:-1])','continue_brt = "n"')
    with open('./dnsrecon/dnsrecon.py', 'w') as f:
        f.write(dnsrecon_data)

    url_list = []
    for domain in domains:
        print '\n [-] Enumerating DNS entries for ' + domain

        dns_records = []
        with open(os.devnull, 'w') as devnull:
            call(['python','./dnsrecon/dnsrecon.py','-d' + domain,'-tstd,brt','-f','-joutput.json'], stdout=devnull, stderr=devnull)
        try:
            dns_records = json.load(open('output.json'))
            os.remove('output.json')
        except:
            time.sleep(2)
            pass

        space_format = 'False'
        for record in dns_records:
            if record.get('name') and record.get('name') not in url_list:
                url_list.append(record.get('name'))
                if space_format == 'False':
                    print ''
                print ' [+] Adding ' + record.get('name')
                space_format = 'True'

    return url_list

# grab all the CloudFront IP ranges
def get_cf_ranges(cf_url):

    ranges = []
    response = urllib2.urlopen(cf_url)
    cf_data = json.load(response)
    for item in cf_data['prefixes']:
        service = item.get('service')
        if service == 'CLOUDFRONT':
            ranges.append(item.get('ip_prefix'))
    return ranges

# check which domains point to CloudFront
def get_cf_domains(ip_ranges,domains):

    print '\n [-] Checking for CloudFront domains...\n'

    cf_domains = []
    found = 'false'
    for domain in domains:
        found = 'false'
        domain_ips = []
        try:
            # this is a tuple and we want the third value
            domain_ips = socket.gethostbyname_ex(domain)[2]
        except:
            print ' [x] Bad URL --> ' + str(domain)
            domain_ips = []
            pass

        for ip in domain_ips:
            for ip_range in ip_ranges:
                ip_network = IPNetwork(ip_range)
                if ip in ip_network:
                    print ' [*] Found CloudFront domain --> ' + str(domain)
                    cf_domains.append(domain)
                    found = 'true'
                    break
                if found == 'true':
                    break
            if found == 'true':
                break

    return cf_domains

# test domains for CloudFront misconfigurations
def find_cf_issues(domains):

    error_domains = []
    for domain in domains:
        try:
            response = urllib2.urlopen('http://' + domain)
        except urllib2.HTTPError, e:
            if e.code == 403 and 'Bad request' in e.fp.read():
                error_domains.append(domain)
        except:
            pass
    return error_domains

def main():

    # 1. Setup the manual information
    logo_msg = '\n CloudFrunt v' + __version__

    epilog_msg = ('example:\n' +
                 ' $ python cloudfrunt.py -l list.txt\n' +
                 logo_msg + '\n A tool for identifying misconfigured CloudFront domains.' +
                 '\n\n NOTE: There are a couple dependencies for this program to work correctly:\n' +
                 '\n 1) pip install netaddr' +
                 '\n 2) pip install dnspython' +
                 '\n 3) git clone https://github.com/darkoperator/dnsrecon.git')

    parser = argparse.ArgumentParser(add_help=False,formatter_class=argparse.RawTextHelpFormatter,epilog=epilog_msg)
    parser.add_argument('-h', '--help', dest='show_help', action='store_true', help='Show this message and exit\n\n')
    parser.add_argument('-l', '--target-file', help='File containing a list of domains (one per line)\n\n', type=str)
    parser.add_argument('-d', '--domains', help='Comma-separated list of domains to scan\n\n', type=str)
    parser.add_argument('-s', '--save', dest='save', action='store_true', help='Save the results to results.txt\n\n')
    parser.add_argument('-N', '--no-dns', dest='no_dns', action='store_true', help='Do not use dnsrecon to expand scope\n')
    parser.set_defaults(show_help='False')
    parser.set_defaults(save='False')
    parser.set_defaults(no_dns='False')
    args = parser.parse_args()

    if args.show_help == True:
        print ''
        print parser.format_help()
        sys.exit(0)

    print logo_msg

    # 2. Grab the list of domains    
    target_list = []

    if not args.target_file and not args.domains:
        print ''
        parser.error('\n\n Either --target-file or --domains is required.\n Or use --help for more info.\n')

    if args.target_file:
        target_list = get_domains(args.target_file)

    if args.domains:
        for domain in [domain.strip() for domain in args.domains.split(',')]:
            target_list.append(domain)

    target_list = list(set(target_list))

    # 3. Expand the list of domains and correct the scope
    if args.no_dns != True:
        if not os.path.isfile('./dnsrecon/dnsrecon.py'):
            print ''
            parser.error('\n\n The file \'./dnsrecon/dnsrecon.py\' was not found.\n Use -N to skip dnsrecon or use --help for more info.\n')
        target_list = get_dnsrecon(target_list)
    
    cf_ranges = get_cf_ranges('https://ip-ranges.amazonaws.com/ip-ranges.json')

    target_list = get_cf_domains(cf_ranges,target_list)

    # 4. Test the domains for CloudFront issues and report them
    if target_list:
        print '\n [-] Testing all CloudFront domains...\n'
        target_list = find_cf_issues(target_list)
    else:
        print ''

    if target_list:
        print ' [!] Found potentially misconfigured CloudFront domains:\n'
        if args.save == True:
            with open('results.txt', 'w') as f:
                print ' [+] Writing output to results.txt...\n'
                for target in target_list:
                    f.write(str(target) + '\n')
        for target in target_list:
            print target
        print ''
    else:
        print ' [x] No misconfigured CloudFront domains found.\n'

if __name__ == '__main__':
    sys.exit(main())
