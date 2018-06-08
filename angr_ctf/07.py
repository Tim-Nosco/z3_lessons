from shared import *

p = angr.Project('07_angr_symbolic_file')

keyfile = 'OJKSQYDP.txt'
s = p.factory.entry_state(addr=0x80488d6)
sm = p.factory.simgr(s)

sm.explore(find=0x08048934)
s = sm.found[0]
sf = s.memory.load(0x0804a0a0, 0x40)
sm.move('found','active')

def goal(state):
	return "Good Job" in state.posix.dumps(1)
logger.info("Starting SYMEXEC")
sm.explore(find=goal)
logger.info("SM: %s", sm)

if sm.found:
	key = sm.found[0].solver.eval(sf, cast_to=str)
	run_bin("/local/{}".format(p.filename), key, cwd='/tmp')

hook(locals())