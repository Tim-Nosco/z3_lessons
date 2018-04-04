import testgen
from z3 import *

def chunks(l, n):
	#(list[int],int) -> list[list[int]]
	for i in range(0,len(l),n):
		yield l[i:i+n]

def columns(l,n):
	#(list[int],int) -> list[list[int]]
	for i in range(n):
		yield l[i::n]

def boxes(l,n):
	#(list[int],int) -> list[list[int]]
	all_chunks = list(chunks(l,n))
	for j in range(0,len(all_chunks),n*n):
		for i in range(j,j+n):
			box = all_chunks[i:i+(n*n):n]
			yield sum(box, [])

if __name__ == '__main__':
	testgen.testgen()
	t, m = testgen.load_testcase()

	s = Solver()
	#make the symbolic board
	symb = [Int("s{}".format(str(i).zfill(2))) for i in range(len(t))]
	#assert the defined values and ranges
	for te, se in zip(t,symb):
		if te:
			#element is defined
			s.add(se==te)
		else:
			#we need to complete
			s.add(se>0)
			s.add(se<=m*m)

	for row in chunks(symb, m*m):
		s.add(Distinct(*row))

	for column in columns(symb, m*m):
		s.add(Distinct(*column))

	for box in boxes(symb, m):
		s.add(Distinct(*box))

	if s.check():
		mo = s.model()
		for c in chunks([mo[e].as_long() for e in symb], m*m):
			print c
	else:
		print "UNSAT"
