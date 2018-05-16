import angr, claripy, z3
import logging
import subprocess
from functools import partial
from itertools import repeat

angr_logger = logging.getLogger()
angr_logger.setLevel(logging.WARNING)
logger = logging.getLogger('solve.py')
logging.basicConfig()
logger.setLevel(logging.INFO)

def hook(s):
	#for debugging
	logger.warning("HOOKING IPYTHON")
	import IPython
	IPython.embed()
	exit(0)

def wall7():
	p = angr.Project('kingdom')
	names = ["R1_shiftl_1",
			 "R1_shiftl_24",
			 "R2_equals_R1_and_0x80000000",
			 "if_R2_le_zero_R1_equals_R1_xor_R3_else_R1"]
	addrs = [p.loader.find_symbol(x).rebased_addr for x in names]

	program_state_addr = 0x1000
	
	instructions = [claripy.BVS("i{}".format(i),8) for i in range(25)]
	start_state = p.factory.blank_state()
	for i in instructions:
		start_state.add_constraints(claripy.Or(*(i==str(x) for x in range(len(addrs)))))

	rounds = [(0x0, 0x0)]

	CRC32Table = p.loader.find_symbol("CRC32Table").rebased_addr
	goal2 = start_state.mem[CRC32Table+0x120].uint32_t.concrete
	rounds.append((0x48, goal2))

	goal3 = start_state.mem[CRC32Table+0x160].uint32_t.concrete
	rounds.append((0x58, goal3))

	goal4 = start_state.mem[CRC32Table+0x300].uint32_t.concrete
	rounds.append((0xc0, goal4))

	goal5 = start_state.mem[CRC32Table+0x3fc].uint32_t.concrete
	rounds.append((0xff, goal5))

	def run_program(s, R1_start, instructions):
		s.mem[program_state_addr+0x0].uint32_t = R1_start
		s.mem[program_state_addr+0x4].uint32_t = 0
		s.mem[program_state_addr+0x8].uint32_t = 0x4c11db7
		s.mem[program_state_addr+0xc].uint32_t = 0

		for instr in instructions:
			logger.info("On instruction: %s", instr)
			functions = [p.factory.callable(x,base_state=s) for x in addrs]
			for i, f in enumerate(functions):
				f(program_state_addr)
				s = s.merge(f.result_state, 
					merge_conditions=[[instr!=str(i)],[instr==str(i)]])[0]
		return s

	s = start_state.copy()
	for R1_start, goal in rounds:
		logger.info("START: %x, GOAL: %x", R1_start, goal)
		s = run_program(s, R1_start, instructions)
		s.add_constraints(s.mem[program_state_addr].uint32_t.resolved==goal)

	res = ''.join(s.solver.eval(x,cast_to=str) for x in instructions)
	logger.info(res)

	#sanity check
	s = p.factory.blank_state()
	for R1_start, goal in rounds:
		r = run_program(s.copy(), R1_start, res)
		logger.info("R1: %x", r.mem[program_state_addr].uint32_t.concrete)
		logger.info("Goal was: %x", goal)

	logger.info("RES: %s", res)

wall7()