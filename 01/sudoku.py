import testgen
from z3 import *

def chunks(l, n):
    """
    (list[A],int) -> list[list[A]]
    Yield successive n-sized chunks from l.
    https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
    """
    for i in range(0, len(l), n):
        yield l[i:i + n]

def columns(l, n):
	"""
	(list[A],int) -> list[list[A]]
	Produces columns of size n from a flattened
		matrix l.
	"""
	for i in range(n):
		yield l[i::n]

def boxes(l,n):
	"""
	(list[A],int) -> list[list[A]]
	Produces sudoku flattened boxes of size n*n 
		from a flattened matrix l.
	"""
	#break the map into groups of n (ex. 3)
	nples = list(chunks(l,n))
	for i in range(0,len(nples),n*n):
		for j in range(i,i+n):
			#(when n=3) j := [0,1,2,9,10,11,18,19,20]
			#extract the nples who create this box
			box = nples[j:j+(n*n):n]
			#flatten box from list[list[Int]] to list[Int]
			box = reduce(lambda a,x: a+x, box, [])
			yield box

def distinct_setup(solver, n, symbol_board):
	#rows must contian the values 1-9
	for row in chunks(symbol_board,n*n):
		solver.add(Distinct(*row))
	#columns must contain the values 1-9
	for column in columns(symbol_board,n*n):
		solver.add(Distinct(*column))
	#boxes must contain the values 1-9
	for box in boxes(symbol_board,n):
		solver.add(Distinct(*box))

#load up a testcase
testgen.testgen()
t, n = testgen.load_testcase()

#initialize the solver and symbolic variables
s = Solver()
symbol_board = [Int("x{}".format(str(i).zfill(2))) for i,_ in enumerate(t)]
#assert that rows, columns, and boxes may not repeat values
distinct_setup(s,n,symbol_board)

#assert the fixed values and ranges for unfixed values
for ti, si in zip(t,symbol_board):
	if ti:
		s.add(si == ti)
	else:
		#if the testcase value was 0, assert the symbolic
		# value must be in (0,n*n]
		s.add(si <= n*n)
		s.add(si > 0)

#print the results
if s.check():
	print "sat"
	m = s.model()
	r = [int(str(m[si])) for si in symbol_board]
	for c in chunks(r,n*n):
		print c

else:
	print "unsat"