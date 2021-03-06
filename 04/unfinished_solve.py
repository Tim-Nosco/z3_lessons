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

def force_range(iter, allowed=hexdigits.lower()):
	#This function yeilds constraints that ensure
	#	members of iter are in the range of allowed chrs
	for x in iter:
		yield claripy.Or(*[x==y for y in allowed])	

def seval(state,expr,**kwargs):
	try:
		r = state.solver.eval(expr,**kwargs)
		logger.info(r)
	except angr.errors.SimUnsatError:
		logger.error("Unsat =(")
		r = None
	return r

class cust_strtoul(angr.SimProcedure):
	def if_builder(self,element,a,x):
		return claripy.If(element==x,claripy.BVV(int(x,16),8*4),a)
	def run(self,src,end,base):
		s = self.state
		logger.info("Made it to strtoul sim.")
		logger.info("Params:\nsrc=%s\nend=%s\nbase=%s\n",src,end,base)
		try:
			all_bytes = [s.memory.load(src+i,1) for i in range(8)]
			total = claripy.BVV(0,8*4)
			for i,b in enumerate(reversed(all_bytes)):
				logger.info("On byte: %s",b)
				f = partial(self.if_builder, b)
				out = reduce(f, hexdigits.lower(), claripy.BVV(0,8*4))
				total += (16*i)+out
		except Exception as e:
			logger.error(e)
			exit(0)
		return total

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
			raise Exception("Unexpected sprintf")
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
p.hook_symbol("strtoul", cust_strtoul())

decrypt_addr = 	0x8048685
decrypt_end = 	0x80486ad
flag_buf_addr = 0x8049b44

flag = claripy.BVS("flag",8*33)
s = p.factory.full_init_state(args=[p.filename,flag])
s.add_constraints(*force_range(imap(flag.get_byte,xrange(32))))

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
	sln = seval(f,flag,cast_to=str)
	if sln:
		logger.info(sln)
		check_flag(sln)