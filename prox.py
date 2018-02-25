
#!/usr/bin/python

import requests
import sys
import time
import random

#URL = sys.argv[1]

proxy_url =             "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt"
outfile =               #YO OUTFILE HERE
user_agents_file =      #USER AGENTS FILE N SHIT
myURL =                 #YO URL HERE

print "[+] Initiating connection..."

def getProxyData(URL,outfile):

        get_proxy_list = requests.session()
        proxy_response = get_proxy_list.get(URL)

        #split contents and trips file header and footer
        #add future code to validate file structure
        url_list = ((proxy_response.content).split('\n'))[4:-2]

        with open(outfile, "w") as f:
                for i in url_list:
                        f.write(i+"\n")
                f.close()

print("[+] Pulling latest proxy list...")

getProxyData(proxy_url, outfile)

with open(outfile, "r") as proxy_list:

        plist = proxy_list.readlines()
        proxy_list.close()

def googlePassedProxies(proxyIPs,checkchar="+"):
        #((i.rstrip()).split(" "))
        return [i for i in proxyIPs if ((i.rstrip()).split(" "))[-1] is checkchar]

def proxysecurity(proxyIPs, security="ssl"):

        #inefficient, but convenient. need to mod this if proxy list gets too huge
        ssl_proxies = []
        nonssl_proxies = []

        for i in proxyIPs:
                line = ((i.split(" "))[1]).split("-")
                if len(line) == 3 and line[2] == "S":
                        ssl_proxies.append(i)
                else:
                        nonssl_proxies.append(i)

        if security == "ssl":
                return ssl_proxies

        elif security == "nonssl":
                return nonssl_proxies

def formatIPs(proxyIPs):

        proxy_dict = {}
        for entry in proxyIPs:

                entry = entry.rstrip()
                entry = entry.split(" ")[0]

                try:

                        (IP, Port) = entry.split(':')

                        proxy_dict[IP] = Port

                except:
                        pass

        return proxy_dict

#Get Google Passed Proxies
googleproxies = googlePassedProxies(plist)

#Define Non-SSL
non_ssl_list = proxysecurity(googleproxies, security="nonssl")
non_ssl_dict = formatIPs(non_ssl_list)

#Define SSL
ssl_list = proxysecurity(googleproxies, security="ssl")
ssl_dict = formatIPs(ssl_list)

#Make request
with open(user_agents_file,"r") as f:
        user_agents = f.readlines()
        f.close()

for i in non_ssl_dict:
        user_agent_str = (random.choice(user_agents)).rstrip()
        user_agent_header = { 'User-Agent': user_agent_str }

        print "[+] User Agent string chosen: %s" % user_agent_str

        http_proxy_url = "http://"+i+":"+non_ssl_dict[i]
        print http_proxy_url

        req_session = requests.Session()
        req_session.headers.update(user_agent_header)

        try:
                req_response = req_session.get(myURL, proxies={'http': http_proxy_url},)
                print req_response

        except:
                print "[-] Request through proxy failed: %s" % i
        time.sleep(2)
