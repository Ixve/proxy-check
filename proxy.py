import requests
import sys
import json

############################################################################################
pxkey = 'proxycheck.io key goes here'                                                      #
apxkey = 'abuseipdb key goes here'                                                         #
############################################################################################


ip = f'{sys.argv[1]}'
l = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719").json()
query = { 'ipAddress': f'{ip}', 'maxAgeInDays': '365' }
headers = { 'Accept': 'application/json', 'Key': f'{apxkey}' }
xs = l["as"].split()[0]


def asn_comparison():
    f = open('asn-list.txt', 'r').read().splitlines()
    if xs in f:
        print('\nPossible proxy detected!\n\nDetection Method: Bad ASN list comparison\nIP: {ip}\nCountry: {l["country"]}\nISP: {l["isp"]}\nASN: {l["as"]}\nRegion Name: {l["regionName"]}\nCity: {l["city"]}')
        exit()    

try:
    asn_comparison()
    try:
        apx = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=query)
        px = requests.get(f"http://proxycheck.io/v2/{ip}?key={pxkey}&vpn=1&asn=1").json()
        ###  load data  ###
        apxr = json.loads(apx.text)
        score = apxr["data"]["abuseConfidenceScore"]
        reports = apxr["data"]["totalReports"]
        proxy = px[f"{ip}"]["proxy"]
        iptype = px[f"{ip}"]["type"]
        ### finish load ###
        if proxy == "yes" or iptype == "VPN": # proxycheck.io
            print(f'\nPossible Proxy Detected!\n\nDetection Method: ProxyCheck.io \nIP: {ip} \nCountry: {l["country"]}, \nISP: {l["isp"]}, \nASN: {l["as"]}, \nRegion Name: {l["regionName"]}, \nCity: {l["city"]}\n\nType: {iptype}\nAbuse Confidence Score: {score}\nTotal Reports: {reports}')
        elif score > 5 or reports > 2: # abuseipdb
            print(f'\nPossibly malicious IP detected!\n\nDetection Method: AbuseIPDB \nIP: {ip} \nCountry: {l["country"]}, \nISP: {l["isp"]}, \nASN: {l["as"]}, \nRegion Name: {l["regionName"]}, \nCity: {l["city"]}\n\nType: {iptype}\nAbuse Confidence Score: {score}\nTotal Reports: {reports}')
        else: # no proxy detected
            print(f'\nNo Proxy/VPN has been detected.\n\nCountry: {l["country"]}, \nISP: {l["isp"]}, \nASN: {l["as"]}, \nRegion Name: {l["regionName"]}, \nCity: {l["city"]}\n\nType: {iptype}\nAbuse Confidence Score: {score}\nTotal Reports: {reports}')

    except Exception as e:
        print(f'An error has occured whilst checking `{ip}`\nInfo: `{e}`')
            
except Exception as e:
    print(f'An error has occured whilst checking `{ip}`\nInfo: `{e}`')

