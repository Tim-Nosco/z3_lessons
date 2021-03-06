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
phash = p.factory.callable(0x080484bb, base_state=s)
flaghashes = p.loader.find_symbol('flaghashes').rebased_addr

solver = claripy.Solver()
fmt = lambda x,y: "{}-{}".format(x,y).ljust(0x20, '\0')

flag = ""
for i in range(44):
	goal = s.mem[flaghashes+i*4].uint32_t.concrete
	for char in printable:
		r = phash(fmt(char,hex(i)[2:].replace('L','')), 0x20)
		r = solver.eval(r,1)[0]
		if r == goal:
			logger.info("found: %s", char)
			flag+=char
			logger.info("flag: %s", flag)
			break

hook()