import angr
import logging, sys
import subprocess

angr_logger = logging.getLogger('angr')
angr_logger.setLevel(logging.INFO)
logger = logging.getLogger(sys.argv[0])
logger.setLevel(logging.DEBUG)

def hook(l):
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

#00, 01, 07, 08, 09, 12, 15, 16, 17