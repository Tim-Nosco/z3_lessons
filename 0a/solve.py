import angr, claripy
import struct
import logging

def hook():
	import IPython
	IPython.embed()
	exit(0)

alogger = logging.getLogger()
alogger.setLevel(logging.INFO)

logger = logging.getLogger('solve.py')
logging.basicConfig()
logger.setLevel(logging.INFO)

p = angr.Project('baby-re', auto_load_libs=False)

CheckSolution_addr = p.loader.find_symbol("CheckSolution").rebased_addr
CheckSolution = p.factory.callable(CheckSolution_addr)

argv = claripy.BVS("all_args", 32*13)
args = [argv.get_bytes(i,4) for i in range(0,13*4,4)]

logger.info("Starting Symbolic Execution")
r = CheckSolution(args)
s = CheckSolution.result_state
logger.info("Symbolic Execution Complete")

logger.info("Attempting to reverse the function")
try:
	resolved_argv = s.solver.eval(argv, extra_constraints=[r!=0])
	logger.info("Got: %s", resolved_argv)
	raw = hex(resolved_argv)[2:].strip('L').decode('hex')
	resolved_args = struct.unpack('<'+'I'*13, raw)
	logger.info("FOUND FLAG: %s", resolved_args)
	logger.info(''.join(map(chr,resolved_args)))
except angr.errors.SimUnsatError:
	logger.error("UNABLE TO FIND FLAG")
	exit(0)
