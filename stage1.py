#!/usr/bin/env python

import requests
import json
import sys
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint
from datetime import datetime

here = Path(__file__).parent.absolute()
repository_root = (here / ".." ).resolve()
sys.path.insert(0, str(repository_root))

import env

inv_url = env.UMBRELLA.get("inv_url")
inv_token = env.UMBRELLA.get("inv_token")
en_url = env.UMBRELLA.get("en_url")
en_key = env.UMBRELLA.get("en_key")
#Use a domain of your choicewww.
print('Type the domain you want to check')
now = datetime.now()
# now.replace('','T')
print(now)
domain = input()
#domain = "www.internetbadguys.com"
sanitized_domain = domain.replace('.', '(dot)')

#Construct the API request to the Umbrella Investigate API to query for the status of the domain
url = f"{inv_url}/domains/categorization/{domain}?showLabels"
headers = {"Authorization": f'Bearer {inv_token}'}
response = requests.get(url, headers=headers)

#And don't forget to check for errors that may have occured!
response.raise_for_status()

#Make sure the right data in the correct format is chosen, you can use print statements to debug your code
domain_status = response.json()[domain]["status"]

if domain_status == 1:
    print(f"The domain {domain} is found CLEAN")
elif domain_status == -1:
    print(f"The domain {domain} is found MALICIOUS")
elif domain_status == 0:
    print(f"The domain {domain} is found UNDEFINED")

print("This is how the response data from Umbrella Investigate looks like: \n")
pprint(response.json(), indent=4)

#Add another call here, where you check the historical data for either the domain from the intro or your own domain and print it out in a readable format

url = f"{inv_url}/pdns/timeline/{domain}"
headers = {"Authorization": f'Bearer {inv_token}'}
response = requests.get(url, headers=headers).json()

for r in response:
    for ip in range(len(r['dnsData'])):
        print("In date " + str(r['date'] + ", the domain" + sanitized_domain + " was mapped to " + str(r['dnsData'][ip]['ipData']['startSeen'])) + ".")

if domain_status == -1:
    #block using Umbrella Enforcement APIs
    url = f"{en_url}/events?customerKey={en_key}"
    url_domains = f"{en_url}/domains?customerKey={en_key}"
    headers = {"Content-Type": 'application/json'}
    now = datetime.now().isoformat()
    payload = {
        "dstDomain" : domain,
        "eventTime" : now + "Z",
        "alertTime" : now + "Z",
        "deviceId" : "ba6a59f4-e692-4724-ba36-c28132c761de",
        "deviceVersion" : "13.7a",
        "dstUrl" : "http://" + domain + "/",
        "protocolVersion" : "1.0a",
        "providerName" : "Security Platform"
        }
    try:
        response_old = requests.get(url_domains, headers=headers)
        response_old.raise_for_status()
        print("the old list of blocked domains is: ")
        for r in response_old.json()['data']:
            print('- ' + str(r['name']))
        print("Now blocking URL " + sanitized_domain)
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        response_new = requests.get(url_domains, headers=headers)
        response_new.raise_for_status()
        print("The new list of blocked domain is: ")
        for r in response_new.json()['data']:
            print('- ' + str(r['name']))
    except Exception as ex:
        print(ex)