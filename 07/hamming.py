import angr, claripy
from itertools import imap
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig()

def hook():
	#for debugging
	import IPython
	IPython.embed()
	exit(0)

#load the binary file
p = angr.Project('ffs')

def get_addr(symb):
	global p
	#look up a symbol with the project's rebased addr
	return p.loader.find_symbol(symb).rebased_addr

#list all of our interesting functions
symbs = ['ffs_ref', 'ffs_imp', 'ffs_imp_nobranch', 'ffs_bug']
#look up each symbol and load the address as a callable
functions = dict(zip(symbs, imap(p.factory.callable, imap(get_addr,symbs))))
#define a BV to hold our function's input
inBV = claripy.BVS("i",32)
#run each function with inBV
results = dict((name, functions[name](inBV)) for name in functions)
#collect the final states
result_states = (x.result_state for x in functions.values())
#merge them all together
state = reduce(lambda a,x: a.merge(x)[0], result_states, p.factory.blank_state())

#see if all the functions match the reference
ref = results['ffs_ref']
for name in symbs[1:]:
	imp = False
	CE = None
	try:
		#attept to find negation
		CE = state.solver.eval(inBV, extra_constraints=[ref != results[name]])
	except angr.errors.SimUnsatError:
		#could not find an instance of function != ref
		imp = True
	logger.info("Did %s match? %s",name,imp)
	if not imp:
		#the eval returned unsat
		logger.info(" CE: %s", hex(CE)[2:].replace('L',''))