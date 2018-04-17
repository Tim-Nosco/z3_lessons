import angr, claripy
from itertools import imap
from functools import partial
from string import digits,letters,punctuation
import logging
import subprocess

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def hook():
	#for debugging
	import IPython
	IPython.embed()
	exit(0)

def hex_nox(x):
	return hex(x)[2:].replace('L','')

def force_range(iter, allowed=digits+letters+punctuation):
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

class cust_sprintf(angr.SimProcedure):
	def if_builder(self,element,a,x):
		return claripy.If(element==x,
			claripy.BVV(hex_nox(x).ljust(2,'\0')),
			a)

	def run(self, dst, fmt, arg1, arg2):
		s = self.state
		fmt = s.mem[fmt].string.concrete
		logger.info("Made it to sprintf sim.\n->dst=%s\n->fmt=%s", dst,fmt)
		# logger.info("arg1=%s\narg2=%s",arg1,arg2)
		if fmt != "%c-%x":
			logger.error("Injected the wrong sprintf")
			exit(1)
		try:
			arg1 = arg1.get_byte(3)
			# logger.info("writing: %s:%s",arg1,seval(s,arg1))
			s.memory.store(dst,arg1)
			s.memory.store(dst+1,'-')
			f = partial(self.if_builder, arg2)
			out = reduce(f, range(0xff), claripy.BVV('\0\0'))
			# logger.info("writing: %s:%s",out,seval(s,out,cast_to=str))
			s.memory.store(dst+2,out)
		except Exception as e:
			logger.error(e)
			exit(0)
		return 4

win  = 0x08048640
lose = 0x08048657

p = angr.Project("./count")
p.hook_symbol('sprintf',cust_sprintf())
flag_len = 0x2c
flag = claripy.BVS("flag",8*flag_len)
argv = [p.filename,flag]
s = p.factory.full_init_state(args=argv)
s.add_constraints(*force_range(imap(flag.get_byte,xrange(flag_len))))

@p.hook(0x80484ff)
def print_flag(state):
    logger.info("FLAG CURRENTLY: %s",seval(state,flag,cast_to=str))

sm = p.factory.simgr(s)
logger.info("Exploring...")
sm.explore(find=win,avoid=lose)
logger.info(sm)

def check_flag(flag):
	argv = [p.filename,flag]
	logger.info("RUNNING: %s", ' '.join(argv))
	logger.info(subprocess.check_output(argv))

for path in sm.found:
	fp = seval(path,flag,cast_to=str)
	logger.info("Found: %s",fp)
	check_flag(fp)

hook()