import angr, claripy
import logging
from string import letters, digits, punctuation
all_chars = map(ord,letters+digits+punctuation)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

p = angr.Project("./count",auto_load_libs=False)

seed = p.factory.entry_state(addr=0x804855a)

for i in range(44):
	start_state = seed.copy()
	round_num = start_state.memory.load(start_state.regs.ebp+0xc,4)
	param1 = start_state.regs.ebp-0x2c
	hash_len = 0x20
	fixed = start_state.memory.load(param1+1,hash_len-1)
	this_char = start_state.memory.load(param1,1)
	hash_tail = "-{}".format(hex(i)[2:]).ljust(hash_len-1,'\0')
	start_state.add_constraints(fixed==hash_tail,
		this_char >= min(all_chars),
		this_char <= max(all_chars),
		round_num == i)

	sm = p.factory.simgr(start_state)
	logger.info("starting search")
	logger.info(sm.explore(find=0x804857a, avoid=0x8048581))
	logger.debug(sm.found)

	for path in sm.found:
		hash_in = path.memory.load(param1,1)
		logger.info("FOUND: %s", path.solver.eval(hash_in,cast_to=str))
