import angr, claripy
from itertools import imap
import logging
from string import letters,digits,punctuation
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def hook():
	#for debugging
	import IPython
	IPython.embed()
	exit(0)

def force_range(iter, allowed=letters+digits+punctuation):
	#This function yeilds constraints that ensure
	#	members of iter are in the range of allowed chrs
	for x in iter:
		yield claripy.Or(*[x==y for y in allowed])	

p = angr.Project("./stirfry")
flag_len = 32
argv = [p.filename, claripy.BVS("sym_arg",8*flag_len)]

s = p.factory.entry_state(args=argv)
flag_bytes = imap(argv[1].get_byte,xrange(flag_len))
s.add_constraints(*force_range(flag_bytes))

sm = p.factory.simgr(s)
logger.info("Starting Explore...")
logger.info(sm.explore(find=0x08048412, avoid=0x80483f6))

for path in sm.found:
	logger.info("FOUND: %s", path.solver.eval(argv[1],cast_to=str))

hook()