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

p = angr.Project('table')

sm = p.factory.simgr()
sm.explore(find=lambda s: "Good Job" in s.posix.dumps(1))

logger.info("sm: %s", sm)
hook(locals())