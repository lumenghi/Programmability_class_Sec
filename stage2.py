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

host = env.AMP.get("host")
client_id = env.AMP.get("client_id")
api_key = env.AMP.get("api_key")

url = f"https://{client_id}:{api_key}@{host}/v1/events"
url_clients = f"https://{client_id}:{api_key}@{host}/v1/computers"
headers = {
    "Accept" : 'application/json',
    "Content-Type" : 'application/json'
    }

response = requests.get(url_clients, headers=headers)
response.raise_for_status()

for data in response.json()['data']:
    if data['hostname'] == 'Demo_AMP_Threat_Audit':
        conn_guid = data['connector_guid']

mac_lists = []

response = requests.get(f"{url}?connector_guid[]={conn_guid}", headers=headers)
response.raise_for_status()
for data in response.json()['data']:
    if data['event_type'] == 'Executed malware':
          for ip in range(len(data['computer']['network_addresses'])):
               mac_lists.append(data['computer']['network_addresses'][ip]['mac'])
               print("On data " + str(data['date']) + " , a new event type " + str(data['event_type']) + " with severity " + str(data['severity']) + " was detected on the device " + str(data['computer']['network_addresses'][ip]['mac']))
          hash_coll = data['file']['identity']['sha256']

#Isolate host
url_is = f"{url_clients}/{conn_guid}/isolation"
try: 
     response = requests.get(url_is, headers=headers)
     response.raise_for_status()
     for device in range(len(mac_lists)):
          print("Device " + str(mac_lists[device]) + " was successfully isolated.")
except Exception as ex:
        print(ex)

host_t = env.THREATGRID.get("host")
api_key_t = env.THREATGRID.get("api_key")

#Get the sample ID in ThreatGrid
url_t = f"https://{host_t}/api/v2/search/submissions?state=succ&q={hash_coll}&api_key={api_key_t}"
try:
     response = requests.get(url_t)
     response.raise_for_status()
     for ip in range(len(response.json()['data']['items'])):
        #  if response.json()['data']['items'][ip]['item']['sha256'] == hash_coll:
             sample_id = response.json()['data']['items'][ip]['item']['sample']
             print('The sample id is: ' + str(sample_id))
except Exception as ex:
    print(ex)

#Get domains in ThreatGrid
domains = []

url_dom = f"https://{host_t}/api/v2/samples/feeds/domains?sample={sample_id}&api_key={api_key_t}"
try:
     response = requests.get(url_dom)
     response.raise_for_status()
     print("Domains for this sample:")
     for ip in range(len(response.json()['data']['items'])):
         print("- " + str(response.json()['data']['items'][ip]['domain']))
         domains.append(response.json()['data']['items'][ip]['domain'])
except Exception as ex:
    print(ex)

with open("domains.txt", 'w') as output:
    for row in domains:
        output.write(str(row) + '\n')