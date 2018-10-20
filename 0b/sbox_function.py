import itertools
import z3

MAXBITS= 3
MAXVAL = 2**MAXBITS
def fmt(x, bits=MAXBITS*2, code='b'):
	return "{{:0{}{}}}".format(bits,code).format(x)

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

def make_vecs():
	upper_half = z3.Function("u", z3.BitVecSort(MAXBITS), 
								z3.BitVecSort(MAXBITS), z3.BitVecSort(MAXBITS))
	lower_half = z3.Function("l", z3.BitVecSort(MAXBITS), 
								z3.BitVecSort(MAXBITS), z3.BitVecSort(MAXBITS))
	mask = ((1<<MAXBITS)-1)
	merged = [z3.Concat(upper_half((i>>MAXBITS)&mask, i&mask), 
						lower_half((i>>MAXBITS)&mask, i&mask)) for i in range(2**(MAXBITS*2))]
	return upper_half,lower_half,merged

def make_sbox(s, vecs=None):
	upper_half,lower_half,_ = make_vecs() if vecs==None else vecs
	#rows and columns
	for i in range(MAXVAL):
		#upper
		s.add(z3.Distinct(*(upper_half(i,j) for j in range(MAXVAL))))
		s.add(z3.Distinct(*(upper_half(j,i) for j in range(MAXVAL))))
		#lower
		s.add(z3.Distinct(*(lower_half(i,j) for j in range(MAXVAL))))
		s.add(z3.Distinct(*(lower_half(j,i) for j in range(MAXVAL))))
		#distinct link
		s.add(z3.Distinct(*(lower_half(j,upper_half(i,j)) \
						for j in range(MAXVAL))))
	#get model
	if s.check()==z3.unsat:
		print z3.unsat
		exit()
	m = s.model()
	#fix upper_half
	resolved_upper = [[m.eval(upper_half(i,j)).as_long() \
					for j in range(MAXVAL)] for i in range(MAXVAL)]
	fixed_upper = [[0 for _ in range(MAXVAL)] for _ in range(MAXVAL)]
	for i in range(MAXVAL):
		for j in range(MAXVAL):
			fixed_upper[j][resolved_upper[i][j]]=i
	#reassemble
	flat = (z3.Concat(z3.BitVecVal(fixed_upper[i][j],MAXBITS), lower_half(i,j)) \
				for j in range(MAXVAL) for i in range(MAXVAL))
	sbox = [m.eval(x,model_completion=True).as_long() for x in flat]
	#print sbox
	fmt_sbox = map(fmt,sbox)
	for row in grouper(fmt_sbox,MAXVAL):
		print row
	fmt_sbox_hex = [fmt(x,2,'x') for x in sbox]
	for row in grouper(fmt_sbox_hex,MAXVAL):
		print row
	with open('/tmp/save.txt', 'w') as f:
		f.write(''.join(fmt_sbox_hex))
	return sbox

def main():
	sbox1 = make_sbox(z3.Solver())
	# s = z3.Solver()
	# k = z3.BitVec("k", 6)
	# u,l,sbox2 = make_vecs()
	# s.add(z3.ForAll([k], 
	# 	z3.Or(*(k^sbox1[x]!=sbox2[x] for x in range(2**(MAXBITS*2))))))
	# sbox2 = make_sbox(s,(u,l,None))
	hook(locals())

if __name__ == '__main__':
	main()