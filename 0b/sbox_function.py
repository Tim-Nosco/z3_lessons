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
def b642ints(str_seq):
	b64_alpha='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	k = dict((x,i) for i,x in enumerate(b64_alpha))
	return [k[x] for x in str_seq]	

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
	return upper_half, lower_half

def make_sbox(s, vecs):
	upper_half,lower_half= vecs
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
	def lb642sb64(x):
		x = int(''.join(map(lambda x: bin(x)[2:].zfill(MAXBITS*2), x)),2)
		x = hex(x)[2:].replace('L','')
		return x.zfill((len(x)+1)//2*2).decode('hex').encode('base64').strip()
	b64_sbox = lb642sb64(sbox)
	print b64_sbox
	fmt_sbox = map(fmt,sbox)
	for row in grouper(fmt_sbox,MAXVAL):
		print row
	with open('/tmp/save.txt', 'w') as f:
		f.write(''.join(b64_sbox))
	return sbox

def main():
	# with open("save.txt", "r") as f:
	# 	data = f.read()
	# sbox1, sbox2, sbox3 = map(b642ints, data.split())[:3]

	s = z3.Solver()
	u,l = make_vecs()
	sbox1 = make_sbox(s, (u,l))
	
	s.reset()
	k = z3.BitVec("k", MAXBITS)
	mask = ((1<<MAXBITS)-1)
	#2nd row (lower part) is different from sbox1
	s.add(z3.ForAll([k], 
		z3.Or(*((k^sbox1[x])&mask != l(x,1) for x in range(MAXVAL)))))
	sbox2 = make_sbox(s,(u,l))

	s.reset()
	s.add(z3.ForAll([k], 
		z3.And(	z3.Or(*((k^sbox1[x])&mask != l(x,1) for x in range(MAXVAL))),
				z3.Or(*((k^sbox2[x])&mask != l(x,1) for x in range(MAXVAL))))))
	sbox3 = make_sbox(s,(u,l))

	hook(locals())

if __name__ == '__main__':
	main()