#!/usr/bin/python
###
# scav.py
#  Search sources for open Elasticsearch instances, and cats the data
# TODO - Add Mongo, S3, Storage Blobs, etc.

import shodan 
import requests
import json

API_KEY = "<SHODAN_API_KEY>"
ipList = [] 
openData = {}
openData['elastic'] = []

###
# searchForData
#  The initial collection of data - hosts open on the right ports, and collect their indices 
def searchForData(api):
    try: 
    # Search for terms
        results_elastic = api.search('product:"Elastic"')
        #print(results_elastic)
        # Show results
        print('Results found: '+str(results_elastic['total']))
        for result in results_elastic['matches']:
            # Get the IPs
            ipList.append(result['ip_str']+':'+str(result['port']))
            print("[*] Adding "+result['ip_str']+':'+str(result['port'])+" to the list...")
            # Get the 'data' element, which contains a shortlist of indices 
            # print(result['data'])
            # print('')
    except shodan.APIError as e:
        print('Error: {}'.format(e))
    return ipList

### 
# accessCheck
#  Check if the elasticsearch does not require authentication to query 
def accessCheck(ipList):
    # Receive the IP List 
    for ip in ipList:
        try: 
        # GET /_cat/indices and collect the indices
            print("[*] Querying http://"+ip+"/_cat/indices")
            r = requests.get('http://'+ip+'/_cat/indices', timeout=5)
            indices = r.text.split(' ')[2]
            
        # If the request was successful, then add the data to our list of things that we can access
            openData['elastic'].append({
                'ip': ip,
                'indices': indices
            })
        except Exception as e:
            continue
    with open('scav-results-elastic.json', 'w') as outfile:
        json.dump(openData, outfile)



def main():
    # Connect to API 
    api = shodan.Shodan(API_KEY)

    # Search for IP addresses
    ipList = searchForData(api)

    # Collect Indices based on the IPs
    accessCheck(ipList)

if __name__ == "__main__":
    main()