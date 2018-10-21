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
def ints2b64(seq_of_ints):
	b64_alpha='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	return ''.join(b64_alpha[x] for x in seq_of_ints)

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

def keyed_sbox(sbox):
	"""
	sbox: list[int]
		This is the original bnum3 sbox loaded in as a list of ints
	return: str
		The return is a new sbox, formatted as a b64 string
	"""
	key = [int(bin(i)[2:].zfill(MAXBITS)*2,2) for i in range(MAXVAL)]
	m = (2**MAXBITS)-1
	def sep(seq):
		return zip(*(((x>>MAXBITS)&m, x&m) for x in seq))
	def merge(u,l):
		return (u<<MAXBITS)|l
	sbox_upper, sbox_lower = sep(sbox)
	key_upper, key_lower = sep(key)
	upper_map = dict(zip(sbox_upper,key_upper))
	lower_map = dict(zip(sbox_lower,key_lower))
	new_sbox = [merge(upper_map[x], lower_map[y]) for x,y in 
						zip(sbox_upper,sbox_lower)]
	print "transformed:", ints2b64(new_sbox)
	return new_sbox

def main():
	# with open("save.txt", "r") as f:
	# 	data = f.read()
	# sbox1, sbox2, sbox3 = map(b642ints, data.split())[:3]

	s = z3.Solver()
	u,l = make_vecs()
	sbox1 = make_sbox(s, (u,l))
	keyed_sbox(sbox1)

	mask = (1<<MAXBITS)-1
	s.add(z3.Or(*(l(i,j)!=(sbox1[(j<<MAXBITS)|i]&mask) for j in range(MAXVAL) for i in range(MAXVAL))))
	sbox2 = make_sbox(s, (u,l))
	keyed_sbox(sbox2)

	hook(locals())

if __name__ == '__main__':
	main()