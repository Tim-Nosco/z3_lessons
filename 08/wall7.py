import angr, claripy, z3
import logging
import subprocess
from functools import partial
from itertools import repeat

angr_logger = logging.getLogger()
angr_logger.setLevel(logging.WARNING)
logger = logging.getLogger('wall7.py')
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
	#extract the component functions
	names = ["R1_shiftl_1",
			 "R1_shiftl_24",
			 "R2_equals_R1_and_0x80000000",
			 "if_R2_le_zero_R1_equals_R1_xor_R3_else_R1"]
	addrs = [p.loader.find_symbol(x).rebased_addr for x in names]
	#this is where we will store the program_state struct
	program_state_addr = 0x1000
	#A sybolic list of instructions 25 long
	instructions = [claripy.BVS("i{}".format(i),8) for i in range(25)]
	start_state = p.factory.blank_state()
	for i in instructions:
		#instructions must be in the range 0 to 4
		start_state.add_constraints(claripy.Or(*(i==str(x) for x in range(len(addrs)))))

	#extracted r1 start values and r1 end values from the binary
	CRC32Table = p.loader.find_symbol("CRC32Table").rebased_addr
	table_lookup = lambda x: start_state.mem[CRC32Table+x].uint32_t.concrete
	rounds = [	(0x00, table_lookup(0x000)),
				(0x48, table_lookup(0x120)),
				(0x58, table_lookup(0x160)),
				(0xc0, table_lookup(0x300)),
				(0xff, table_lookup(0x3fc))	]

	def run_program(s, R1_start, instructions):
		#initialize the program_state struct
		s.mem[program_state_addr+0x0].uint32_t = R1_start
		s.mem[program_state_addr+0x4].uint32_t = 0
		s.mem[program_state_addr+0x8].uint32_t = 0x4c11db7
		s.mem[program_state_addr+0xc].uint32_t = 0
		#go through each instruction, trying each possible function
		for instr in instructions:
			logger.debug("On instruction: %s", instr)
			#set the functions' base_state to the currently collected state
			functions = [p.factory.callable(x,base_state=s) for x in addrs]
			for i, f in enumerate(functions):
				#run the function with the program_state's address as an arg
				f(program_state_addr)
				#merge the resulting state into the collector state
				# only use this state's values if the instruction at this
				# position was the one matching the current function
				s = s.merge(f.result_state, 
					merge_conditions=[[instr!=str(i)],[instr==str(i)]])[0]
		#return the value in R1
		return s.mem[program_state_addr].uint32_t.resolved
	#c_state will collect all the goal constraints for our final eval
	c_state = start_state.copy()
	for R1_start, goal in rounds:
		logger.info("START: %x, GOAL: %x", R1_start, goal)
		#run the program being sure not to modify the starting state
		# but also using the same set of instructions as every other
		# starting R1 value
		r = run_program(start_state.copy(), R1_start, instructions)
		#assert the result must be our goal value
		c_state.add_constraints(r==goal)
	#synthesize a program!
	logger.info("Asking z3 for a satisfying program.")
	res = ''.join(c_state.solver.eval(x,cast_to=str) for x in instructions)
	logger.info("GOT: %s",res)
	#sanity check
	logger.info("Running sanity check for program synthesis")
	s = p.factory.blank_state()
	for R1_start, goal in rounds:
		#run the program with a concrete set of instructions
		r = run_program(s.copy(), R1_start, res)
		logger.info("R1:       %x", s.solver.eval(r))
		logger.info("Goal was: %x", goal)
	logger.info("PROGRAM: %s", res)
	return [res]

if __name__ == '__main__':
	wall7()
