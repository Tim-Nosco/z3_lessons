import z3

#all instructions, a string to print the instruction and a
# lambda function to execute it.
op_codes = {
	0x00: ("r1 = r1 + r1", 	lambda a,b,c,d: (a+a,b,c,d)),
	0x01: ("r1 = r1 + r2", 	lambda a,b,c,d: (a+b,b,c,d)),
	0x02: ("r1 = r1 + r3", 	lambda a,b,c,d: (a+c,b,c,d)),
	0x03: ("r1 = r1 + r4", 	lambda a,b,c,d: (a+d,b,c,d)),
	0x04: ("r2 = r2 + r1", 	lambda a,b,c,d: (a,b+a,c,d)),
	0x05: ("r2 = r2 + r2", 	lambda a,b,c,d: (a,b+b,c,d)),
	0x06: ("r2 = r2 + r3", 	lambda a,b,c,d: (a,b+c,c,d)),
	0x07: ("r2 = r2 + r4", 	lambda a,b,c,d: (a,b+d,c,d)),
	0x08: ("r3 = r3 + r1", 	lambda a,b,c,d: (a,b,c+a,d)),
	0x09: ("r3 = r3 + r2", 	lambda a,b,c,d: (a,b,c+b,d)),
	0x0a: ("r3 = r3 + r3", 	lambda a,b,c,d: (a,b,c+c,d)),
	0x0b: ("r3 = r3 + r4", 	lambda a,b,c,d: (a,b,c+d,d)),
	0x0c: ("r4 = r4 + r1", 	lambda a,b,c,d: (a,b,c,d+a)),
	0x0d: ("r4 = r4 + r2", 	lambda a,b,c,d: (a,b,c,d+b)),
	0x0e: ("r4 = r4 + r3", 	lambda a,b,c,d: (a,b,c,d+c)),
	0x0f: ("r4 = r4 + r4", 	lambda a,b,c,d: (a,b,c,d+d)),
	0x10: ("r1 = r1 ^ r1", 	lambda a,b,c,d: (a^a,b,c,d)),
	0x11: ("r1 = r1 ^ r2", 	lambda a,b,c,d: (a^b,b,c,d)),
	0x12: ("r1 = r1 ^ r3", 	lambda a,b,c,d: (a^c,b,c,d)),
	0x13: ("r1 = r1 ^ r4", 	lambda a,b,c,d: (a^d,b,c,d)),
	0x14: ("r2 = r2 ^ r1", 	lambda a,b,c,d: (a,b^a,c,d)),
	0x15: ("r2 = r2 ^ r2", 	lambda a,b,c,d: (a,b^b,c,d)),
	0x16: ("r2 = r2 ^ r3", 	lambda a,b,c,d: (a,b^c,c,d)),
	0x17: ("r2 = r2 ^ r4", 	lambda a,b,c,d: (a,b^d,c,d)),
	0x18: ("r3 = r3 ^ r1", 	lambda a,b,c,d: (a,b,c^a,d)),
	0x19: ("r3 = r3 ^ r2", 	lambda a,b,c,d: (a,b,c^b,d)),
	0x1a: ("r3 = r3 ^ r3", 	lambda a,b,c,d: (a,b,c^c,d)),
	0x1b: ("r3 = r3 ^ r4", 	lambda a,b,c,d: (a,b,c^d,d)),
	0x1c: ("r4 = r4 ^ r1", 	lambda a,b,c,d: (a,b,c,d^a)),
	0x1d: ("r4 = r4 ^ r2", 	lambda a,b,c,d: (a,b,c,d^b)),
	0x1e: ("r4 = r4 ^ r3", 	lambda a,b,c,d: (a,b,c,d^c)),
	0x1f: ("r4 = r4 ^ r4", 	lambda a,b,c,d: (a,b,c,d^d)),
	0x20: ("r1 = r1 <<< 7", lambda a,b,c,d: (z3.RotateLeft(a,7),b,c,d)),
	0x21: ("r2 = r2 <<< 7", lambda a,b,c,d: (a,z3.RotateLeft(b,7),c,d)),
	0x22: ("r3 = r3 <<< 7", lambda a,b,c,d: (a,b,z3.RotateLeft(c,7),d)),
	0x23: ("r4 = r4 <<< 7", lambda a,b,c,d: (a,b,c,z3.RotateLeft(d,7))),
	0x24: ("swap(r1,r2)",   lambda a,b,c,d: (b,a,c,d)),
	0x25: ("swap(r1,r3)",   lambda a,b,c,d: (c,b,a,d)),
	0x26: ("swap(r1,r4)",   lambda a,b,c,d: (d,b,c,a)),
	0x27: ("swap(r2,r3)",   lambda a,b,c,d: (a,c,b,d)),
	0x28: ("swap(r2,r4)",   lambda a,b,c,d: (a,d,c,b)),
	0x29: ("swap(r3,r4)",   lambda a,b,c,d: (a,b,d,c))
}
REGSIZE = 32
TARGET_BNUM=5
def tuple2bv(t):
	#turn a 4-element-tuble into it's long bv form
	t = list(t)
	return z3.simplify(reduce(lambda a,x: z3.Concat(a,x), t[1:], t[0]))

def bv2gen(bv):
	#turn a large bitvec into its corresponding 4-element-tuple state
	return (z3.simplify(z3.Extract(REGSIZE-1+i,i,bv)) for i in reversed(range(0,bv.size(),REGSIZE)))

def op_tree(instr, state):
	#build a huge if-tree that looks something like:
	#if instr==0:
	#	r1 = r1 + r1
	#elif instr==1:
	#	... for all instr in op_codes ...
	#else:
	#	NOP
	for key, (_, f) in op_codes.items():
		#the z3.If construct needs a single bv for the true/false
		# arguments, so we cant use the convienent tuple form
		state = z3.If(instr==key, tuple2bv(f(*bv2gen(state))), state)
	return state

def run_program(program, state):
	for instr in program:
		state = op_tree(instr,state)
	return z3.simplify(state)

def print_program(program, m = None):
	print "PROGRAM:"
	concrete = []
	for instr in program:
		if m!=None:
			#if a z3.ModelRef is provided, construct the concrete
			# representation of the program
			instr = m.eval(instr, model_completion=True).as_long()
			concrete.append(instr)
		#print the instruction, if the instruction DNE, it is a NOP
		print op_codes.get(instr,('NOP',))[0]
	return concrete

def hamming_approx(a):
	num_pos = a.size()/4
	m1 = int("5"*num_pos,16)
	m2 = int("3"*num_pos,16)
	#c contains a 1 in every two-bit pair if either corresponding bit 
	# is set in a
	b0 = a & m1
	b1 = z3.LShR(a,1) & m1
	c = b0 | b1
	#e contains a 1 in every four-bit pair if any of the corresponding
	# four bits are set in a
	d0 = c & m2
	d2 = z3.LShR(c,2) & m2
	e = d0 | d2
	e = z3.simplify(e)
	#sum each nibble's lsb
	t = reduce(lambda a,x:a+(z3.LShR(e,x)&1),range(0,a.size(),4),0)
	return t

def branch_number(in1,in2,program):
	diff = in1^in2
	#from sean, `branch_number = Hw(a^b)+Hw(P(a^b))`
	return hamming_approx(diff)+hamming_approx(run_program(program,diff))

def make_testcase(state):
	#convert a tuple of python ints to a long bitvec
	return tuple2bv(z3.BitVecVal(i,REGSIZE) for i in state)

def test():
	#for the lulz
	program = [0,0]
	start_state = (1,0,0,0)
	print "START STATE: {}".format(start_state)
	print_program(program)
	state = make_testcase(start_state)
	result = bv2gen(run_program(program,state))
	print "RESULT STATE: {}".format(map(z3.simplify, result))

def gen_program(s1,s2,ps1,ps2,bns,program,testcases):
	#tries to find if there exists an [s1,s2,program] 
	# that satisfies our assertions, if it finds one,
	# but does not satisfy the greater qbf, it returns
	# a counterexample that can be used for skolemization
	s = z3.Solver()
	for x,y,px,py,bn in testcases:
		#assume x!=y (because we would not save a testcase of x==y)
		#assert that program is invertable (forall[s1,s2], s1!=s2 -> ps1!=ps2) 
		# and that the branch_number is > the target branch number
		s.add(px!=py, bn>=TARGET_BNUM)
		#the program currently finishes if we do not assert the branch number
		# and only assert invertability
		# s.add(px!=py)
	#assert that the (s1, s2, program) solution has the 
	# target bnum and 1:1 map
	s.add(z3.Implies(s1!=s2, z3.And(ps1!=ps2, bns>=TARGET_BNUM)))
	#again, asserting only invertability to prove bnum is the problem
	# s.add(z3.Implies(s1!=s2, ps1!=ps2))
	#multiple programs:
	# s.add(z3.Or(*(x!=y for x,y in zip(program,[36, 29, 11, 18, 20]))))
	# s.set("timeout",3*60*1000)
	print "Checking Satisfiablity..."
	r = s.check()
	if r != z3.sat:
		#this will happen if the solver times out or is unsat
		print r
		return None
	print "Concretizing program..."
	m = s.model()
	#c becomes a concrete version of the satisfiable program 
	c = print_program(program, m)
	print c
	#run s1 and s2 (symbolic) through the concrete program
	cs1 = run_program(c,s1)
	cs2 = run_program(c,s2)
	#remove all clauses from the solver
	s.reset()
	#assert the inverse of our invertability and target bnum goals
	print "Finding a counterexample..."
	s.add(z3.Not(z3.Implies(s1!=s2, z3.And(cs1!=cs2,
			branch_number(s1,s2,c)>=TARGET_BNUM))))
	#prove that bnum is the problem and not invertability
	# s.add(z3.Not(z3.Implies(s1!=s2,cs1!=cs2)))
	r = s.check()
	if r == z3.sat:
		#there exists a counterexample, skolemize
		m = s.model()
		t1 = m.eval(s1).as_long()
		t2 = m.eval(s2).as_long()
		del s
		print "new testcase: {}".format((hex(t1),hex(t2)))
		return (t1, t2)
	elif r==z3.unsat:
		#there does not exist a counterexample to our claim,
		# this program for sure has all attributes we want
		print "proved"
		return None
	else:
		#the solver timed out
		print r
		return None

def main():
	#create a symbolic program
	program = []
	for i in range(5):
		x = z3.BitVec('pc{}'.format(i),7)
		program.append(x)
	#two symbolic inputs will be used to make assertions
	# about the program
	s1,s2 = z3.BitVecs('s1 s2',REGSIZE*4)
	#create the symbolic output variables for s1 and s2
	print "Running Program 3+3*len(testcases)"
	ps1 = run_program(program,s1)
	ps2 = run_program(program,s2)
	bns = run_program(program,s1^s2)
	#run each concrete input through the symbolic program
	testcases = []
	def prepare_test(x,y):
		#run x,y:python ints through the symbolic program
		x = z3.BitVecVal(x,REGSIZE*4)
		y = z3.BitVecVal(y,REGSIZE*4)
		px = run_program(program,x)
		py = run_program(program,y)
		bn = branch_number(x,y,program)
		return x,y,px,py,bn
	with open("testcases.txt", "r") as f:
		for line in f:
			testcases.append(prepare_test(*eval(line)))
	print "ran program {}x".format(len(testcases)*3+3)
	#gen_program will make a new solver object and create assertions
	g = gen_program(s1,s2,ps1,ps2,bns,program,testcases)
	#call gen_program until we can prove it has the desired traits
	while g!=None:
		testcases.append(prepare_test(*g))
		g = gen_program(s1,s2,ps1,ps2,bns,program,testcases)
	#print out the testcases as a "quicksave"
	for x,y,_,_,_ in testcases:
		print "{}".format((x,y))
	#enter interactive mode so state is preserved for manual analysis
	import IPython
	IPython.embed()

if __name__ == '__main__':
	main()