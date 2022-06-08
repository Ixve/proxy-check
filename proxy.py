import requests
import sys
import json
import socket
from cymruwhois import Client
from discord_webhook import DiscordWebhook

c = Client()
url = 'Put your webhook URL here'
ip = f'{sys.argv[1]}'

r = c.lookup(ip)
l = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719").json()
try:
    x = open('asn-list.txt', 'r')
    f = x.read().splitlines()
    asn = r.asn
    if r.asn in f:
        hook = DiscordWebhook(url=url, rate_limit_retry=True, content=f'Possible Proxy Detected! Info: \nIP: `{ip}` \nCountry: `{l["country"]}`, \nISP: `{l["isp"]}`, \nASN: `{l["as"]}`')
        z = hook.execute()
    else:
        pass

except Exception as e:
    hook = DiscordWebhook(url=url, rate_limit_retry=True, content=f'An error has occured whilst checking `{ip}`\nInfo: `{e}`')
    z = hook.execute()
