import angr
import claripy
import logging
from string import letters, digits, punctuation

logger = logging.getLogger()
logger.setLevel(logging.INFO)

#load the project
p = angr.Project('./ftp', auto_load_libs=False)
#this is the address of the hash function
hash_func_addr = 0x0401540

#guess the password length
pw_len = 6
#make the password bitvec
password = claripy.BVS("sym_arg", pw_len*8).concat('\n\0')
#when we enter the password we have to enter a newline
# also to make our argument to the hash function a pointer
# we must convert the password bv to an array
h_in = map(password.get_byte, xrange(pw_len+2))

#we make a state here so we can assert some constraints on the
# inputs to the hash. The PW characters must be
# letters, digits, or punctuation
s = p.factory.blank_state()
s.add_constraints(*(i!='\0' for i in h_in[:-2]))

#Load the hashing function as a python function (using the base
# constraints we specified above)
hasher = p.factory.callable(hash_func_addr, base_state=s)
#finally call the function with our symbolic input
# collect the return value and the resulting state
logger.info("Symbolic Execution...")
res1 = hasher(h_in)
s = hasher.result_state

def cust_hash(pw):
	I = claripy.BVV(0x1505, 32)
	for x in pw:
		I = (I * 0x21) + x.sign_extend(32-8)
	return I.zero_extend(32)

res2 = cust_hash(h_in[:-1])
equiv = s.solver.eval(res1==res2)
logger.info(equiv)
if not equiv:
	CE = s.solver.eval(password, extra_constraints=[res1!=res2])
	logger.info(hex(CE)[2:].replace('L',""))

