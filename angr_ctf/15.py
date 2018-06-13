from shared import *

p = angr.Project("15_angr_arbitrary_read")

s = p.factory.entry_state()
sm = p.factory.simgr(s)

logger.info("Starting SYMEXEC")
sm.explore(find=0x08048525)
logger.info("SM: %s", sm)

if sm.found:
	s = sm.found[0]
	s.add_constraints(s.regs.eax==0x484f4a47)
	if s.satisfiable():
		run_bin(p.filename, s.posix.dumps(0))

hook(locals())