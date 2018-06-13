from shared import *

p = angr.Project("16_angr_arbitrary_write")

s = p.factory.entry_state()
sm = p.factory.simgr(s)

def goal(state):
	return "Good Job" in state.posix.dumps(1)

logger.info("Starting SYMEXEC")
sm.explore(find=0x0804860c)
logger.info("SM: %s", sm)

if not sm.found:
	logger.error("uhoh")
	hook(locals())

pw = p.loader.find_symbol("password_buffer").rebased_addr
s = sm.found[0]
s.add_constraints(s.stack_read(0,4)==pw)
logger.info("is sat: %s", s.satisfiable())
sm.move("found","active")

logger.info("Starting SYMEXEC2")
sm.explore(find=goal)
logger.info("SM: %s", sm)

if not sm.found:
	logger.error("uhoh2")
	hook(locals())

run_bin(p.filename, sm.found[0].posix.dumps(0))

hook(locals())