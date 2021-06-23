#!/usr/bin/python

import requests
import re
import socket
from hashlib import md5
import time
import sys

def tomd5(s):
    m = md5()
    m.update(s)
    return m.hexdigest()

if len(sys.argv) < 3:
    print("Usage: emdeefive.py <HOST_IP> <PORT>")
    exit()
else:      
    targhost =  sys.argv[1]
    targport = int(sys.argv[2])

#Manually build the http requests and send raw
http_req = """GET / HTTP/1.1\r
Host: {targhost}:{targport}\r
User-Agent: Mozilla/5.0 \r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r
Accept-Language: en-US,en;q=0.5\r
Accept-Encoding: text\r
Connection: close\r
Upgrade-Insecure-Requests: 1\r
Cache-Control: max-age=360\r
\r\n\r\n
"""

http_post = """POST / HTTP/1.1\r
Host: {targhost}:{targport}\r
User-Agent: Mozilla/5.0 \r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r
Content-Length: {cl}\r
Accept-Encoding: text\r
Content-Type: application/x-www-form-urlencoded\r
Origin: http://{targhost}:{targport}/\r
Referer: http://{targhost}:{targport}/\r
Cookie: PHPSESSID={cookie}\r
Upgrade-Insecure-Requests: 1\r
\r
hash={hash}"""

#Set up two connections to remote host
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.connect((targhost,targport))
s2.connect((targhost,targport))

#RegEx to find the string to hash
token_re = 'h3.+?>(.+?)</h3>'

s1.send(http_req.format(targhost=targhost, targport=targport))
print("[+] Sent http request.")

#Parse out cookie, and token
res_str = ''
while 1:
    res_str += s1.recv(1)   
    if res_str.endswith("\n"): 
        #Parse cookie line            
        if res_str.startswith("Set-Cookie:"):
            cookie = ((res_str.split(": ")[1]).split(";")[0]).split("=")[1]          
        #Get the token
        token = (re.findall(token_re, res_str))
        if token:        
            token = token[0]            
            hash = tomd5(token)
            #Once token is grabbed, break out and leave the HTTP connection open
            #leaving the buffer in limbo
            break
        #Debug the response            
        #print(res_str)     
        res_str = '' 

print("[+] Cookie: {}".format(cookie))  
print("[+] Got token {} with hash {}".format(token, hash))

post_data = http_post.format(targhost=targhost, 
                            targport=targport,
                            hash=hash, 
                            cl=(len(hash)+5),
                            cookie=cookie)
print(post_data)
#Send the second request with other connection buffer still waiting to read
s2.send(post_data)
final = s2.recv(1024)
print(final)
     
