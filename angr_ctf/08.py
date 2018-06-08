from shared import *

p = angr.Project('08_angr_constraints')

s = p.factory.entry_state()
sm = p.factory.simgr(s)

def goal(state):
	return "Good Job" in state.posix.dumps(1)
logger.info("Starting SYMEXEC")
sm.explore(find=0x08048673)
logger.info("SM: %s", sm)
if not sm.found:
	logger.error('uhoh')
s = sm.found[0]
password = p.loader.find_symbol('password').rebased_addr
password = s.memory.load(password,16)
buf = p.loader.find_symbol('buffer').rebased_addr
buf = s.memory.load(buf,16)
s.add_constraints(password==buf)

if sm.found:
	run_bin(p.filename, s.posix.dumps(0))

hook(locals())