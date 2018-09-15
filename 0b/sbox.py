import itertools
import z3

MAXBITS= 3
MAXVAL = 2**MAXBITS
def fmt(x, bits=MAXBITS):
	return "{{:0{}b}}".format(bits).format(x)

def flatten(x):
	return list(itertools.chain.from_iterable(x))
def grouper(i, n):
	return itertools.izip_longest(*([iter(i)] * n))

def hook(l=None):
	if l:
		locals().update(l)
	import IPython
	IPython.embed(banner1="",confirm_exit=False)
	exit()

def main():
	upper_half = [[z3.BitVec("u({},{})".format(fmt(i),fmt(j)),MAXBITS) \
					for j in range(MAXVAL)] for i in range(MAXVAL)]
	lower_half = [[z3.BitVec("l({},{})".format(fmt(i),fmt(j)),MAXBITS) \
					for j in range(MAXVAL)] for i in range(MAXVAL)]
	s = z3.Solver()
	#rows and columns
	for i in range(MAXVAL):
		#upper
		s.add(z3.Distinct(*(upper_half[i][j] for j in range(MAXVAL))))
		s.add(z3.Distinct(*(upper_half[j][i] for j in range(MAXVAL))))
		#lower
		s.add(z3.Distinct(*(lower_half[i][j] for j in range(MAXVAL))))
		s.add(z3.Distinct(*(lower_half[j][i] for j in range(MAXVAL))))
	#flatten and join
	flat = [z3.Concat(x,y) for x,y in zip(flatten(upper_half), 
											flatten(lower_half))]
	#no repeats
	s.add(z3.Distinct(*flat))
	#get model
	if s.check()==z3.unsat:
		print z3.unsat
		exit()
	m = s.model()
	sbox = [m.eval(x,model_completion=True).as_long() for x in flat]
	#print sbox
	fmt_sbox = [fmt(x,MAXBITS*2) for x in sbox]
	for row in grouper(fmt_sbox,MAXVAL):
		print row
	hook(locals())

if __name__ == '__main__':
	main()