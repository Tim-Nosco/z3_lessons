import angr, claripy, z3
import logging
import subprocess
from functools import partial
from itertools import repeat

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
	gcd_addr = p.loader.find_symbol('gcd').rebased_addr
	gcd = p.factory.callable(gcd_addr, base_state=s)
	logger.info("starting symbolic execution: gcd(%s, %s)",arg1,arg2)
	r = gcd(arg1,arg2)
	s = gcd.result_state
	s.add_constraints(r==0x3a)
	logger.info("evaluating arguments")
	return map(str,(s.solver.eval(arg1), s.solver.eval(arg2)))

table_lookups = []
def Te4_lookup(s):
	#use the global list to save offset/result pairs
	global table_lookups
	#do some logging
	count = len(table_lookups)
	logger.info("Te4 inject at %s:%s.", count/4, hex(s.addr)[2:].replace('L',''))
	#only 256 options for the offset (from AL)
	offset = s.regs.rax[7:0]
	#make a new bv and assert that it equals the collected AST (save space in the list)
	index = claripy.BVS("idx{}".format(count),8)
	s.add_constraints(index==offset)
	#make a new result array (just the same byte repeated 4 times)
	result = claripy.BVS("res{}".format(count),8)
	s.regs.rax = reduce(lambda a,x: a.concat(x), 
						repeat(result,3), 
						result).zero_extend(32)
	#save the tuple for later assertions (in a z3.Function)
	table_lookups.append((index,result))

#these instructions are a symbolic table read from Te4. they look like:
# 0040378c 	8b 04 85    	MOV  EAX,[Te4 + RAX*0x4]
#			a0 90 60 00
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
	#setup the key to expand
	logger.info("setting up sym args")
	key = claripy.BVS('key', 8*16)
	keyarr = [key.get_byte(i) for i in range(16)]
	#Make sure angr only uses 1 solver
	s = p.factory.blank_state(remove_options={angr.options.COMPOSITE_SOLVER})
	s.add_constraints(*[k!='\0' for k in keyarr])

	logger.info("starting symbolic execution on aes")	
	aes_addr = p.loader.find_symbol('malicious_aes_test').rebased_addr
	aes = p.factory.callable(aes_addr, base_state=s)
	#when calling the function, use the python list so angr makes a pointer
	r = aes(keyarr)
	s = aes.result_state
	s.add_constraints(r==3)

	#now we are going to use the tuples generated by Te4_lookup
	# we will build a z3 function then use a symbolic index
	# this is much faster than state.memory.load with a symbolic addr
	z3_table = z3.Function("Te4", z3.BitVecSort(8), z3.BitVecSort(8))
	#there is only one solver because we specified no composite solver option
	z3_solver = s.solver._solver._get_solver()
	#extract the Te4 table from program memory and turn it into a z3 func
	Te4 = p.loader.find_symbol("Te4").rebased_addr
	for i in range(256):
		z3_solver.add(z3_table(i)==s.mem[Te4+i*4].uint8_t.concrete)
	#for each tuple saved in Te4_lookup, conver to z3 bv then 
	# assert that the index and result are related via the z3 function
	for e in table_lookups:
		idx, res = map(claripy.backends.z3.convert, e)
		z3_solver.add(z3_table(idx)==res)
	#ensure the problem is sat
	logger.info("Checking satisfiability")
	query = z3_solver.check()
	logger.info(query)
	assert(query==z3.sat)
	logger.info("Getting model")
	m = z3_solver.model()
	#make our function's input a z3 bv
	z3key = claripy.backends.z3.convert(key)
	def long_to_str(l):
		return hex(l)[2:].replace('L','').decode('hex')
	resolved_key = long_to_str(m[z3key].as_long())
	logger.info("KEY: %s", repr(resolved_key))
	# KEY: 'ACHIEVEMENTAWARD'
	return [resolved_key]

def wall10():
	global p
	logger.info("setting up sym args")
	keylen = 0x2
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
argv += wall1() # ('174','116')
argv += wall2() # ['ACHIEVEMENTAWARD']
argv += ['a']*5
argv += ['B'*5]
# argv += wall10()
test_run(argv)
argv +=[claripy.BVS("argv{}".format(i),8*3) for i in range(len(argv),wall_zero+1)]
