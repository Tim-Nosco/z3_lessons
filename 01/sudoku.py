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
	nples = chunks(l,n)
	for i in range(n*n):
		

def distinct_setup(solver, n, symbol_board):
	#rows must contian the values 1-9
	for row in chunks(symbol_board,n*n):
		solver.add(Distinct(*row))
	#columns must contain the values 1-9
	for column in columns(symbol_board,n*n):
		solver.add(Distinct(*column))
	#boxes must contain the values 1-9
	for box in boxes(symbol_board,n):
		print box
		solver.add(Distinct(*box))

testgen.testgen()
t, n = testgen.load_testcase()

s = Solver()
symbol_board = [Int("x{}".format(str(i).zfill(2))) for i,_ in enumerate(t)]
distinct_setup(s,n,symbol_board)
