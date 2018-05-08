import z3
import logging
logger = logging.getLogger('optimize.py')
logging.basicConfig()
logger.setLevel(logging.INFO)

def hook():
	#for debugging
	logger.warning("HOOKING IPYTHON")
	import IPython
	IPython.embed()

s1 = z3.Solver()
x, y = z3.Ints('x y')
s1.add(x>y)
s1.add(x==4)

s = z3.Optimize()
s.add(*s1.assertions())
m = s.maximize(y)
s.check()


logger.info("max: %s", m)

hook()