from shared import *

p = angr.Project("00_angr_find")

s = p.factory.entry_state()
sm = p.factory.simgr(s)
logger.info("Starting SYMEXEC")
sm.explore(find=0x0804867d, avoid=0x0804866b)
logger.info("FOUND: %s", sm)
if sm.found:
	key = sm.found[0].posix.dumps(0)
	run_bin(p.filename, key)

hook(locals())