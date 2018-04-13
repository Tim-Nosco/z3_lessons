import angr
import claripy
import logging
from string import letters, digits, punctuation

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def force_range(iter, allowed=letters+digits+punctuation):
	#This function yeilds constraints that ensure
	#	members of iter are in the range of allowed chrs
	all_chrs = map(ord, allowed)
	min_chr = min(all_chrs)
	max_chr = max(all_chrs)
	for x in iter:
		yield claripy.And(min_chr<=x, x<=max_chr)	

#load the project
p = angr.Project('./ftp', auto_load_libs=False)
#this is the address of the hash function
hash_func_addr = 0x0401540
#this is the address of the hash value we want to reverse
hash_target_addr = 0x0401753+1

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
printable = force_range(h_in[:-2])
s.add_constraints(*printable)

#Load the hashing function as a python function (using the base)
# constraints we specified above
hasher = p.factory.callable(hash_func_addr, base_state=s)
#finally call the function with our symbolic input
# collect the return value and the resulting state
logger.info("Symbolic Execution...")
res = hasher(h_in)
s = hasher.result_state

#pull the target hash value out of the program's memory and
# assert it as a constraint for the hash output
goal = s.mem[hash_target_addr].uint32_t.concrete
s.add_constraints(res==goal)

#solve for the password
logger.info("Solving for goal: %s", hex(goal))
pw = s.solver.eval(password, cast_to=str)
logger.info("FOUND PASSWORD: %s", pw)
logger.info("Works? %s", hasher(pw)==goal)