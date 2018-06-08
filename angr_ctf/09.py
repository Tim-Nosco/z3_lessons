from shared import *
from functools import partial
p = angr.Project('09_angr_hooks')

def pw_eq_buf(eax, state):
	logger.info("Hook called from %x", state.history.parent.addr)
	pw = state.memory.load(p.loader.find_symbol('password').rebased_addr,0x10)
	buf = state.memory.load(p.loader.find_symbol('buffer').rebased_addr,0x10)
	state.add_constraints(pw==buf)
	state.regs.eax = eax
p.hook(0x080486b3, partial(pw_eq_buf, 1), length=5)
p.hook(0x0804872d, partial(pw_eq_buf, 0), length=5)

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