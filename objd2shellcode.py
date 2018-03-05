#!/usr/bin/python
#Take output from ObjDump and format into shellcode

import sys
import os
import re

try:
	objdump_file = sys.argv[1]
	os.path.isfile(objdump_file)

except:
	print "Invalid Filename or File doesn't exist"
	sys.exit(0)

with open(objdump_file,'r') as f:
	file_contents = f.readlines()

hex_reg = re.compile(r'\s([a-f0-9]{2})')

byte_string = ''

for i in file_contents:
	i = i.split('\t')
	if len(i) == 3:
		i = i[1].rstrip()
		byte_string += i+' '

format_to_bytearray = ''.join("\\x"+i for i in (byte_string.split()))

print format_to_bytearray

