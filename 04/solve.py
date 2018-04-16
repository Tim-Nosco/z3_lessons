import angr, claripy, archinfo
import logging
from itertools import imap
from string import hexdigits
from struct import unpack, pack

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def force_range(iter, allowed=hexdigits):
	for x in iter:
		yield claripy.Or(*(y==x for y in allowed))

def chunks(l, n):
	#(list[int],int) -> list[list[int]]
	for i in range(0,len(l),n):
		yield l[i:i+n]

def hook():
	import IPython
	IPython.embed()
	exit(0)

p = angr.Project("./philosophersstone", auto_load_libs=False)

s = p.factory.blank_state(addr=0x080484bb)

def flag_loc(state):
	return [state.mem[0x8049b44+4*i].uint32_t.resolved for i in range(4)]

flag = [claripy.BVS("x{}".format(i),8*4) for i in range(4)]
for i,x in enumerate(flag):
	s.memory.store(0x8049b44+4*i, x)

sm = p.factory.simgr(s)
logger.info("Starting Explore...")
logger.info(sm.explore(find=0x08048506))

for path in sm.found:
	enc = flag_loc(path)
	target = chunks("1935957e45db5adb595ed84c2c0ea435".decode('hex'),4)
	target = [claripy.BVV(unpack(">I",x)[0],4*8) for x in target]
	constraints = zip(enc, target)
	# print constraints
	# hook()
	path.add_constraints(*[x==y for x,y in constraints])

	fp = [pack("<I",path.solver.eval(x)) for x in flag]
	fp = ''.join(fp).encode('hex')
	logger.info("FLAG: %s", fp)

