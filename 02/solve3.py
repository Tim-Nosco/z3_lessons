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

p = angr.Project('./count')

# count = 0
# @p.hook(0x80485c7)
# def inc_count(state):
# 	global count
# 	count+=1

# s = p.factory.full_init_state(add_options=angr.options.unicorn)
# f = p.factory.callable(0x0804851f,base_state=s)
argv = [p.filename,"a".ljust(0x2c,"A")]
s = p.factory.full_init_state(args=argv,add_options=angr.options.unicorn)
hook()
