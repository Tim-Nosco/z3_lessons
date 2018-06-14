import angr
import logging, sys

angr_logger = logging.getLogger('angr')
angr_logger.setLevel(logging.INFO)
logger = logging.getLogger(sys.argv[0])
logger.setLevel(logging.DEBUG)

p = angr.Project('07_angr_symbolic_file')

#enter the program after the "ignore_me" call
s = p.factory.entry_state(addr=0x80488d6)
sm = p.factory.simgr(s)

def goal(state):
	return "Good Job" in state.posix.dumps(1)
logger.info("Starting SYMEXEC")
sm.explore(find=goal)
logger.info("SM: %s", sm)

if sm.found:
	#This line errors at:
	# raise SimMemoryLimitError("Concrete size %d outside of allowable limits" % i)
	key = sm.found[0].fs.unlinks[0][1].concretize()