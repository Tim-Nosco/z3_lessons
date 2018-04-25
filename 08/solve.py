import angr, claripy, z3
import logging
import subprocess

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

count = 0
def Te4_lookup(s):
	global count
	logger.info("Te4 inject at %s:%s.", count/4, hex(s.addr)[2:].replace('L',''))
	offset = s.regs.rax[7:0]
	Te4 = p.loader.find_symbol("Te4").rebased_addr
	def builder(a,x):
		return claripy.If(offset==x, s.mem[Te4+x*4].uint32_t.concrete, a)
	tmp = reduce(builder, range(256), claripy.BVV(0,8*4))
	s.regs.rax = tmp
	count+=1
	# if count/4 == 10:
	# 	angr_logger.setLevel(logging.DEBUG)

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
	s = p.factory.blank_state()
	#ensure the rk start values are 0
	s.add_constraints(*[k!='\0' for k in keyarr])
	rk_start = s.regs.rbp + 32
	for i in range(60):
		s.memory.store(rk_start+4*i, claripy.BVV(0,8*4))
	#make the Te4 lookup table
	Te4_table = z3.Function("Te4", z3.BitVecSort(8), z3.BitVecSort(32))
	#to get a z3 solver: s._solver_backend.solver()
	#todo make conditions stay in s
	#todo turn claripybv into z3bv

	logger.info("starting symbolic execution on aes")	
	aes_addr = p.loader.find_symbol('rijndaelKeySetupEnc').rebased_addr
	aes = p.factory.callable(aes_addr, base_state=s)
	r = aes(rk_start,keyarr,0x80)
	s = aes.result_state
	rk_final = [s.memory.load(rk_start+4*i,4) for i in range(60)]
	magic = 0x28
	hook(locals())
	s.add_constraints(	rk_final[magic+0]==0x048a97a0,
						rk_final[magic+1]==0xac9a53b7,
						rk_final[magic+2]==0xd37fd65b,
						rk_final[magic+3]==0x15cf1362)
	logger.info("Asking sat solver for key")
	try:
		resolved = s.solver.eval(key,cast_to=str)
	except angr.errors.SimUnsatError:
		logger.error("UNSAT!")
		hook(locals())
	logger.info("KEY: %s",resolved)
	logger.info(resolved.encode('hex'))
	hook(locals())

argv = [p.filename]
argv += ('174','116')# wall1()
argv += wall2()
test_run(argv)
argv +=[claripy.BVS("argv{}".format(i),8*3) for i in range(len(argv),wall_zero+1)]
# s = p.factory.full_init_state(args=argv, add_options=angr.options.unicorn)
# sm = p.factory.simgr(s)
# print sm.explore(find=0x0400905)