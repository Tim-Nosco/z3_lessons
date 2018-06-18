import angr, claripy
import logging, sys
import subprocess

#setup some logging
angr_logger = logging.getLogger('angr')
angr_logger.setLevel(logging.INFO)
logger = logging.getLogger(sys.argv[0])
logger.setLevel(logging.DEBUG)

def hook(l):
	#useful for debugging. call like hook(locals())
	locals().update(l)
	import IPython
	IPython.embed()
	exit(0)

def run_bin(fname, stdin, **kwargs):
	if '/' != fname[0]:
		fname = './'+fname
	logger.info("RUNNING: %s with %s", fname, repr(stdin))
	p = subprocess.Popen([fname],
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, **kwargs)
	out = p.communicate(input="{}\n".format(stdin))
	logger.info("RESULT: %s", out)

p = angr.Project('table')

def table_lookup(state):
	#unconstrain eax, save start and end eax
	lookups = state.globals.get('lookups', [])
	old_value = state.regs.eax[7:]
	new_value = claripy.BVS('l{}'.format(hex(state.addr)), 8)
	lookups.append((old_value.ast,new_value))
	state.regs.eax=new_value
	state.globals['lookups'] = lookups
#hook all the table lookups
addrs = """
00400628
00400662
0040069c
004006d6
00400710
0040074a
00400784
004007be
004007ff
00400839
00400873
004008ad
004008e7
00400921
0040095b
00400995
"""
for addr in [int(x,16) for x in addrs.split()]:
	p.hook(addr, table_lookup, length=7)

s = p.factory.entry_state(remove_options={angr.options.COMPOSITE_SOLVER})
sm = p.factory.simgr(s)
sm.explore(find=lambda s: "Good Job" in s.posix.dumps(1))
logger.info("sm: %s", sm)
s = sm.found[0]

import z3
#extract the z3 solver object
solver = s.solver._solver._get_solver()
#create a z3 table to constrain the lookup bitvecs
table = z3.Array('table', z3.BitVecSort(8), z3.BitVecSort(8))
table_start_addr = p.loader.find_symbol('table').rebased_addr
#assert the actual table values
for i in range(256):
	solver.add(table[i]==s.mem[table_start_addr+i].uint8_t.concrete)
#constrain the lookups saved in table_lookup hooks
for e in s.globals.get('lookups',[]):
	i, r = map(claripy.backends.z3.convert, e)
	solver.add(table[i]==r)
#Create the model
logger.info(solver.check())
m = solver.model()
#extract the concrete stdin bv from the model
def l2s(l):
	return hex(l)[2:].replace('L','').decode('hex')
inp = claripy.backends.z3.convert(s.posix.stdin.content[0][0])
key=l2s(m[inp].as_long())

logger.info("key: %s", key)

run_bin(p.filename, key)


hook(locals())