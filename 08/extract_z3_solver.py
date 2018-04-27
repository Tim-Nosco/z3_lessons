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
	rk_start = s.regs.rbp + 32
	for i in range(60):
		s.memory.store(rk_start+4*i, claripy.BVV(0,8*4))

	logger.info("starting symbolic execution on aes")	
	aes_addr = p.loader.find_symbol('rijndaelKeySetupEnc').rebased_addr
	aes = p.factory.callable(aes_addr, base_state=s)
	r = aes(rk_start,keyarr,0x80) #todo args are int*, char*, int?
	s = aes.result_state
	rk_final = [s.memory.load(rk_start+4*i,4) for i in range(60)]

	magic = 0x28
	s.add_constraints(	rk_final[magic+0]==0x048a97a0,
						rk_final[magic+1]==0xac9a53b7,
						rk_final[magic+2]==0xd37fd65b,
						rk_final[magic+3]==0x15cf1362)

	#make the Te4 lookup table
	Te4 = p.loader.find_symbol("Te4").rebased_addr
	Te4_table = [(x,s.mem[Te4+x*4].uint8_t.concrete) for x in range(256)]
	z3_table = z3.Function("Te4", z3.BitVecSort(8), z3.BitVecSort(8))
	z3_solver = s.solver._solver._get_solver()
	for i, e in Te4_table:
		z3_solver.add(z3_table(i)==e)
	global table_lookups
	for idx, res in table_lookups:
		idx = claripy.backends.z3.convert(idx)
		res = claripy.backends.z3.convert(res)
		z3_solver.add(z3_table(idx)==res)
	logger.info("Checking satisfiability")
	logger.info(z3_solver.check())
	logger.info("Getting model")
	m = z3_solver.model()
	z3key = claripy.backends.z3.convert(key)
	resolved_key = hex(m[z3key].as_long())[2:].replace('L','').decode('hex')
	logger.info("KEY: {}".format(repr(resolved_key)))
	#KEY: '7\xf0\x18T\xb7\x04S\xf9\x99\x0cy\xeb\x96\xed^\xb6'

	hook(locals())

argv = [p.filename]
argv += ('174','116')# wall1()
argv += wall2()
test_run(argv)
argv +=[claripy.BVS("argv{}".format(i),8*3) for i in range(len(argv),wall_zero+1)]
# s = p.factory.full_init_state(args=argv, add_options=angr.options.unicorn)
# sm = p.factory.simgr(s)
# print sm.explore(find=0x0400905)