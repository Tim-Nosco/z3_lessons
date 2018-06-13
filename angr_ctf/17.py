from shared import *

p = angr.Project("17_angr_arbitrary_jump")

s = p.factory.entry_state()
sm = p.factory.simgr(s,save_unconstrained=True)

logger.info("Starting SYMEXEC")
sm.run()
logger.info("SM: %s", sm)

if not sm.unconstrained:
	logger.error("UHOH")
	hook(locals())

goal = p.loader.find_symbol("print_good").rebased_addr
s = sm.unconstrained[0]
s.add_constraints(s.ip == goal)
logger.info("is sat? %s", s.satisfiable())

run_bin(p.filename, s.posix.dumps(0))

