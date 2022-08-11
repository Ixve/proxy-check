import requests
import sys
import json
import socket
from cymruwhois import Client

c = Client()
ip = f'{sys.argv[1]}'

pxkey = '! ProxyCheck.io API Key goes here !'
apxkey = '! AbuseIPDB API Key goes here !'

r = c.lookup(ip)
l = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719").json()

try:
    x = open('asn-list.txt', 'r')
    f = x.read().splitlines()
    asn = r.asn
    if r.asn in f:
        print(f'(asncomparison)\nPossible Proxy Detected! Info: \nIP: {ip} \nCountry: {l["country"]}, \nISP: {l["isp"]}, \nASN: {l["as"]}, \nRegion Name: {l["regionName"]}, \nCity: {l["city"]}')
        x.close()
    else:
        try:
            x.close()
            query = { 'ipAddress': f'{ip}', 'maxAgeInDays': '365', }
            headers = { 'Accept': 'application/json', 'Key': f'{apxkey}', }
            apx = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=query)
            apxr = json.loads(apx.text)
            with open('data.json', 'w') as f:                
                apxd = json.dump(apxr, f, sort_keys=True)
                f.close()
            with open('data.json', 'r') as f:
                apxd = json.load(f)
                score = apxd["data"]["abuseConfidenceScore"]
                reports = apxd["data"]["totalReports"]

            px = requests.get(f"http://proxycheck.io/v2/{ip}?key={pxkey}&vpn=1&asn=1").json()
            proxy = px[f"{ip}"]["proxy"]
            iptype = px[f"{ip}"]["type"]
            if proxy == "yes":
                print(f'(proxycheck)\nPossible Proxy Detected! Info: \nIP: {ip} \nCountry: {l["country"]}, \nISP: {l["isp"]}, \nASN: {l["as"]}, \nRegion Name: {l["regionName"]}, \nCity: {l["city"]}\n\nType: {iptype}\nAbuse Confidence Score: {score}\nTotal Reports: {reports}')
            elif iptype == "VPN":
                print(f'(proxycheck)\nPossible VPN Detected! Info: \nIP: {ip} \nCountry: {l["country"]}, \nISP: {l["isp"]}, \nASN: {l["as"]}, \nRegion Name: {l["regionName"]}, \nCity: {l["city"]}\n\nType: {iptype}\nAbuse Confidence Score: {score}\Total Reports: {reports}')
            elif score > 5 or reports > 2:
                print(f'(abuseipdb)\nPossible Malicious IP Detected! Info: \nIP: {ip} \nCountry: {l["country"]}, \nISP: {l["isp"]}, \nASN: {l["as"]}, \nRegion Name: {l["regionName"]}, \nCity: {l["city"]}\n\nType: {iptype}\nAbuse Confidence Score: {score}\Total Reports: {reports}')
            else:
                print(f'No Proxy/VPN Detected. IP Info: \nCountry: {l["country"]}, \nISP: {l["isp"]}, \nASN: {l["as"]}, \nRegion Name: {l["regionName"]}, \nCity: {l["city"]}\n\nType: {iptype}\nAbuse Confidence Score: {score}\nTotal Reports: {reports}')

        except Exception as e:
            print(f'An error has occured whilst checking `{ip}`\nInfo: `{e}`')
            
except Exception as e:
    print(f'An error has occured whilst checking `{ip}`\nInfo: `{e}`')
