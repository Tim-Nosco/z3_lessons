from shared import *

p = angr.Project("02_angr_find_condition")

s = p.factory.entry_state()
sm = p.factory.simgr(s)

def goal(state):
	return "Good Job" in state.posix.dumps(1)
logger.info("Starting SYMEXEC")
sm.explore(find=goal)
logger.info("SM: %s", sm)

if sm.found:
	run_bin(p.filename, sm.found[0].posix.dumps(0))

hook(locals())