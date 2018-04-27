import angr, claripy, z3
import logging
import subprocess
from functools import partial

angr_logger = logging.getLogger()
angr_logger.setLevel(logging.INFO)
logger = logging.getLogger('solve.py')
logging.basicConfig()
logger.setLevel(logging.INFO)

def hook(s):
	#for debugging
	logger.warning("HOOKING IPYTHON")
	import IPython
	IPython.embed()
	exit(0)

wall_zero = 0xc
def test_run(argv):
	if len(argv) < wall_zero:
		argv += ['a']*(wall_zero-len(argv))
	logger.info("testing with the following command:\n%s",argv)
	logger.info(subprocess.call(argv))

p = angr.Project('./kingdomv2', auto_load_libs=False)

def wall1():
	global p
	arg1, arg2 = [claripy.BVS("arg{}".format(i), 8) for i in (1,2)]
	s = p.factory.blank_state()
	s.add_constraints(arg1!=0x3a, arg2!=0x3a)
	gcd = p.factory.callable(p.loader.find_symbol('gcd').rebased_addr, 
					base_state=s)
	logger.info("starting symbolic execution: gcd(%s, %s)",arg1,arg2)
	r = gcd(arg1,arg2)
	s = gcd.result_state
	s.add_constraints(r==0x3a)
	logger.info("evaluating arguments")
	return map(str,(s.solver.eval(arg1), s.solver.eval(arg2)))

table_lookups = []
def Te4_lookup(s):
	global table_lookups
	count = len(table_lookups)
	logger.info("Te4 inject at %s:%s.", count/4, hex(s.addr)[2:].replace('L',''))
	offset = s.regs.rax[7:0] #todo is the asm: mov rax, [Te4+4*AL]
	index = claripy.BVS("idx{}".format(count),8)
	s.add_constraints(index==offset)
	result = claripy.BVS("res{}".format(count),8)
	s.regs.rax = result.concat(result).concat(result).concat(result).zero_extend(32)
	table_lookups.append((index,result))
	count+=1
	# if count/4 == 10:
	# 	angr_logger.setLevel(logging.DEBUG)

#these instructions are a symbolic table read from Te4
p.hook(0x0040378c, Te4_lookup, length=7)
p.hook(0x004037a5, Te4_lookup, length=7)
p.hook(0x004037bb, Te4_lookup, length=7)
p.hook(0x004037d1, Te4_lookup, length=7)

def chunks(l, n):
	#(list[int],int) -> list[list[int]]
	for i in range(0,len(l),n):
		yield l[i:i+n]

def wall2():
	global p
	logger.info("setting up sym args")
	key = claripy.BVS('key', 8*16)
	keyarr = [key.get_byte(i) for i in range(16)]
	s = p.factory.blank_state(remove_options={angr.options.COMPOSITE_SOLVER})
	#ensure the rk start values are 0
	s.add_constraints(*[k!='\0' for k in keyarr])

	logger.info("starting symbolic execution on aes")	
	aes_addr = p.loader.find_symbol('malicious_aes_test').rebased_addr
	aes = p.factory.callable(aes_addr, base_state=s)
	r = aes(keyarr)
	s = aes.result_state
	s.add_constraints(r==3)

	#make the Te4 lookup table
	Te4 = p.loader.find_symbol("Te4").rebased_addr
	Te4_table = [s.mem[Te4+x*4].uint8_t.concrete for x in range(256)]
	logger.info("Starting symbolic lookups.")
	total = str(len(table_lookups)).zfill(2)
	def builder(offset,a,x):
		return claripy.If(x==offset, Te4_table[x], a)
	for i,e in enumerate(table_lookups):
		k,v = e
		logger.info("Doing lookup number %s/%s", str(i+1).zfill(2), total)
		mux = reduce(partial(builder,k),range(256),claripy.BVV(0,8))
		s.add_constraints(mux==v)

	logger.info("Done with lookups.")

	logger.info("Evaluating key.")
	resolved_key = s.solver.eval(key,cast_to=str)
	logger.info("FOUND: %s", repr(resolved_key))
	# FOUND: 'ACHIEVEMENTAWARD'
	return [resolved_key]

def wall10():
	global p
	logger.info("setting up sym args")
	keylen = 0x1d
	key = claripy.BVS('key', 8*keylen)
	keyarr = [key.get_byte(i) for i in range(keylen)]
	s = p.factory.blank_state()
	s.add_constraints(*[k!='\0' for k in keyarr])

	logger.info("starting symbolic execution on crc")	
	crc_addr = p.loader.find_symbol('crc32_test').rebased_addr
	crc = p.factory.callable(crc_addr, base_state=s)
	r = crc(keyarr)
	s = crc.result_state
	s.add_constraints(r==3)
	logger.info("Checking satisfiabliity")
	resolved_key = s.solver.eval(key,cast_to=str)
	logger.info("FOUND: %s", repr(resolved_key))
	return [resolved_key]

argv = [p.filename]
argv += ('174','116')# wall1()
argv += ['ACHIEVEMENTAWARD']#wall2()
argv += ['a']*5
argv += ['B'*5]
argv += wall10()
test_run(argv)
argv +=[claripy.BVS("argv{}".format(i),8*3) for i in range(len(argv),wall_zero+1)]
