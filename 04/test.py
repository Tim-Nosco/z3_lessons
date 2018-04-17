import angr, claripy, archinfo
import logging
from string import hexdigits
from struct import unpack
from functools import partial
from itertools import imap
import subprocess

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def hook():
	#for debugging
	import IPython
	IPython.embed()
	exit(0)

def chunks(l, n):
	#(list[int],int) -> list[list[int]]
	for i in range(0,len(l),n):
		yield l[i:i+n]

def seval(state,expr,**kwargs):
	try:
		r = state.solver.eval(expr,**kwargs)
		logger.info(r)
	except angr.errors.SimUnsatError:
		logger.error("Unsat =(")
		r = None
	return r

class cust_sprintf(angr.SimProcedure):
	def if_builder(self,element,a,x):
		return claripy.If(element==int(x,16),x,a)

	def run(self, dst, fmt, arg1):
		s = self.state
		fmt = s.mem[fmt].string.concrete
		logger.info("Made it to sprintf sim.\n->dst=%s\n->fmt=%s", dst,fmt)
		logger.debug("arg=%s",arg1)
		if fmt != "%lx":
			logger.error("Injected the wrong sprintf")
			return 0
	
		for in_idx, b in enumerate(map(arg1.get_byte,xrange(4))):
			out_idx = 2*in_idx
			for i in range(7,0,-4):
				nibble = b[i:i-3]
				logger.debug("nibble: %s",nibble)
				f = partial(self.if_builder, nibble)
				out = reduce(f, hexdigits.lower(), claripy.BVV(0,8))
				# logger.debug("result: %s",chr(seval(s,out)))
				logger.debug("stored at: %s", out_idx)
				s.memory.store(dst+out_idx,out)
				out_idx+=1
		return 8

p = angr.Project("./philosophersstone", auto_load_libs=False)
p.hook_symbol("sprintf", cust_sprintf())

decrypt_addr = 	0x8048685
decrypt_end = 	0x80486ad
flag_buf_addr = 0x8049b44
s = p.factory.blank_state(addr=decrypt_addr)

#ensure the input location is symbolic
flag = claripy.BVS("flag",8*16)
s.memory.store(flag_buf_addr, flag)

logger.info("Starting Explore...")
sm = p.factory.simgr(s)
sm.explore(find=decrypt_end,avoid=0x80486bf)
logger.info(sm)

def hex_nox(x):
	return hex(x)[2:].replace('L','')

def check_flag(flag):
	argv = [p.filename,sln]
	logger.info("RUNNING: %s", ' '.join(argv))
	logger.info(subprocess.check_output(argv))

for f in sm.found:
	sln = seval(f,flag)
	if sln:
		sln = hex_nox(sln).decode('hex')
		sln = ''.join([c[::-1] for c in chunks(sln,4)]).encode('hex')
		logger.info("Found flag: %s",sln)
		check_flag(sln)