#!/usr/bin/python

import re
import sys
import subprocess as subp

shell_code = []
for i in subp.check_output(['objdump','-d', sys.argv[1]).split('\n'):
	i = i.strip()
	byte_list = re.findall(r'(?<=:\t)([a-z0-9\s]{1,20})',i)
	for bytes in byte_list:	
		shell_code.append(bytes.strip())

print (' '.join(shell_code)).replace(' ',',\\x')
