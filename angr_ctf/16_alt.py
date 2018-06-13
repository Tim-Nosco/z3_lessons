from shared import *

p = angr.Project("16_angr_arbitrary_write")

s = p.factory.entry_state(add_options={angr.options.SYMBOLIC_WRITE_ADDRESSES})
sm = p.factory.simgr(s)

def goal(state):
	return "Good Job" in state.posix.dumps(1)

logger.info("Starting SYMEXEC")
sm.explore(find=goal)
logger.info("SM: %s", sm)

if not sm.found:
	logger.error("uhoh2")
	hook(locals())

run_bin(p.filename, sm.found[0].posix.dumps(0))

hook(locals())