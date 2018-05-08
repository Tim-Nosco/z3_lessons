import angr, claripy
from itertools import imap
from functools import partial
from string import printable
import logging
import subprocess

angrLogger = logging.getLogger()
angrLogger.setLevel(logging.WARNING)

logger = logging.getLogger('solve3.py')
logging.basicConfig()
logger.setLevel(logging.INFO)


def hook():
	#for debugging
	import IPython
	IPython.embed()
	exit(0)

p = angr.Project('./count', use_sim_procedures=False)

s = p.factory.blank_state(mode="tracing")
check_flag_char_addr = p.loader.find_symbol("check_flag_char").rebased_addr
check_flag_char = p.factory.callable(check_flag_char_addr, base_state=s)

solver = claripy.Solver()
flag = ""
for i in range(44):
	for char in printable:
		guess = claripy.BVV(char).zero_extend(32-8)
		r = check_flag_char(guess,i)
		r = solver.eval(r,1)[0]
		if r==1:
			logger.info("FOUND: %s", char)
			flag+=char
			logger.info("FLAG: %s", flag)
			break
hook()