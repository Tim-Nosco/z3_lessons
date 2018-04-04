import os

def load_testcase(fname='tests/test1'):
	"""
	(str) -> list[int]

	fname: a string of the testcase filename.
	return: None if error, otherwise a list of
		the testcase as integer values.
	"""
	try:
		# Read in the testcase file
		with open(fname, 'r') as f:
			data = f.read()
		# Flatten the data into a single array of integers
		# grid = reduce(lambda a, x: a+map(int, x.split(' ')), 
		# 		data.split('\n'), [])
		grid = map(int, data.split())
		n = grid[-1]
		grid = grid[:-1]
		assert(len(grid)==n*n*n*n)
		return grid, n
	except Exception as e:
		print e
		return None

def testgen():
	"""
	(None) -> None
	Creates testcase files for use by sudoku.py
	"""
	if not os.path.isdir('tests'):
		os.makedirs('tests')
	with open('tests/test1', 'w') as f:
		f.write("5 0 7 9 0 0 0 0 4\n")
		f.write("0 8 0 6 1 0 0 0 0\n")
		f.write("9 0 3 0 4 0 0 8 6\n")
		f.write("0 0 0 0 0 8 0 9 7\n")
		f.write("0 0 8 7 0 6 1 0 0\n")
		f.write("7 5 0 1 0 0 0 0 0\n")
		f.write("1 4 0 0 3 0 7 0 5\n")
		f.write("0 0 0 0 7 2 0 3 0\n")
		f.write("3 0 0 0 0 1 8 0 9 3")

if __name__ == "__main__":
	testgen()
	print load_testcase()

