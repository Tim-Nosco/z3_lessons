from shared import *

p = angr.Project("01_angr_avoid")

s = p.factory.entry_state()
sm = p.factory.simgr(s)

avoid = p.loader.find_symbol("avoid_me").rebased_addr
def goal(state):
	return "Good Job" in state.posix.dumps(1)
logger.info("Starting SYMEXEC")
sm.explore(find=goal, avoid=avoid)
logger.info("SM: %s", sm)

if sm.found:
	run_bin(p.filename, sm.found[0].posix.dumps(0))

hook(locals())