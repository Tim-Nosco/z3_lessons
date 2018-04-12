#!/usr/bin/python2.7
"""
"Boy, that hash function looks kind of annoying to reverse..."
The problem claims this binary has a difficult to reverse hash function,
	that makes this a non-optimal solution, but let's test it's theory.
Key reference:
https://github.com/angr/angr-doc/blob/master/CHEATSHEET.md
"""

import angr, claripy
import logging
from string import letters, digits, punctuation
all_chars = map(ord,letters+digits+punctuation)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

#load the program 
p = angr.Project("./count")

#focus on the startpoint of the hash function: 0x080484bb
f = p.factory.callable(0x080484bb)
#every call to the hash uses a 0x20 byte array
hash_len = 0x20
#the first four characters will be something like a-0\0 or Z-20
var_len = 4
#fin will hold our symbolic hash array
fin = claripy.BVS('sym_arg', 8*hash_len)
#call the function with the array and 0x20
res = f(fin, hash_len)
#load the final state of the function run
state = f.result_state
#the first character of the input array is the interesting flag character
var_chr = fin.get_bytes(0,1)
#it should be a letter, digit, or punctuation character
state.add_constraints(var_chr >= min(all_chars),
 					  var_chr <= max(all_chars))

#flag will collect our solved constraints
flag = ""
#there is a hardcoded lenth of 44 characters
for i in range(44):
	#format the fixed part of the input to be like c-HH where c is the char
	# to learn and HH is the hex value of the current index, i
	fixed = "-{}".format(hex(i)[2:]).ljust(hash_len-1,'\0')
	#the hash results are stored in an unsigned int array starting at 0x08049a00
	ith_hash = state.mem[0x08049a00+4*i].long.concrete
	tmp=[res == ith_hash,
		fin.get_bytes(1,hash_len-1) == fixed]
	#ask z3 to solve for the value of the flag byte
	e = state.solver.eval(var_chr, extra_constraints=tmp)
	#record the solver's response
	logger.info("FOUND: %s", e)
	flag += chr(e)
	logger.info("-> %s", flag)
