from base64 import b64encode, b64decode
from random import sample

MAXBITS= 4
MAXVAL = 2**MAXBITS

def hook(l=None):
	if l:
		locals().update(l)
	import IPython
	IPython.embed(banner1="",confirm_exit=False)
	exit()

def ror(val, r_bits, max_bits):
	return ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
		(val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def read_sbox():
	with open('save.txt','r') as f:
		data = f.read()
	s = map(ord, data.decode('hex'))
	m = (2**3)-1
	s = zip(*(((x>>3)&m, x&m) for x in s))
	return [(u<<MAXBITS)|l for u,l in zip(*s)]

def expand_sbox(s0):
	s1_key = [(x<<MAXBITS)|y for x,y in zip(range(8,16),range(8,16))]
	s2_key = [(x<<MAXBITS)|y for x,y in zip(range(0, 8),range(8,16))]
	s3_key = [(x<<MAXBITS)|y for x,y in zip(range(8,16),range(0, 8))]
	s1 = keyed_sbox(s0, s1_key)
	s2 = keyed_sbox(s0, s2_key)
	s3 = keyed_sbox(s0, s3_key)
	s0 = ''.join(map(chr,s0))
	s  = ''.join(s0[x:8+x]+s1[x:8+x] for x in range(0,8*8,8))
	s += ''.join(s2[x:8+x]+s3[x:8+x] for x in range(0,8*8,8))
	return map(ord,s)

def gen_key():
	"""
	The key is MAXVAL many elements which consist of unique upper halves
		and lower halves.
	"""
	c = range(MAXVAL)
	u = sample(c,MAXVAL)
	l = sample(c,MAXVAL)
	return [(x<<MAXBITS)|y for x,y in zip(u,l)]

def keyed_sbox(sbox,key):
	"""
	sbox: list[int]
		This is the original bnum3 sbox loaded in as a list of ints
	key: list[int]
		This key has special properties, should be generated like in gen_key
	return: str
		The return is a new sbox, formatted as a string
	"""
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
	return ''.join(map(chr,new_sbox))

def sub(m,sbox):
	"""
	m: str
		a raw string to be substituted. for consistent results len(m)%3==0
	sbox: str
		a b64 encoded sbox (such as the output of keyed_sbox)
	"""
	k = dict(zip(map(chr,range(256)),sbox))
	return ''.join(k[x] for x in m)

def propagate(message):
	def swap(l,i,j):
		t = l[i]
		l[i]=l[j]
		l[j]=t
	block_size = (len(message)*8)/4
	ml = int(message.encode('hex'),16)
	m = (1<<block_size)-1
	p = [(ml>>(block_size*i))&m for i in range(4)]
	p[0]=ror(p[0], 1, block_size)
	p[0]=p[0]^m
	p[1]=ror(p[1], 1, block_size)
	p[1]=p[1]^p[2]
	p[2]=p[2]^p[0]
	p[0]=(p[0]+p[1])&m
	p[3]=p[3]^p[0]
	swap(p,0,2)
	swap(p,2,3)
	swap(p,1,3)
	r = reduce(lambda a,x:a|(p[x]<<(block_size*x)), range(4), 0)
	return hex(r)[2:].replace('L','').zfill(len(message)*2).decode('hex')

def encrypt_round(m, sbox):
	return propagate(sub(m, sbox))

def encrypt(m, rounds, sbox):
	return reduce(lambda a,_: encrypt_round(a,sbox), range(rounds), m)

def analysis(p0,p1,ksbox):
	print "------------"
	def fmt(x): return x.encode('hex').zfill(6)
	def diff(x,y): return hex(int(fmt(x),16)^int(fmt(y),16))[2:].replace('L',"").zfill(6)
	print "single round."
	print fmt(p0), fmt(p1)
	c0 = encrypt(p0, 1, ksbox)
	c1 = encrypt(p1, 1, ksbox)
	print fmt(c0), fmt(c1)
	print "start diff:", diff(p0,p1)
	print "end diff:  ", diff(c0,c1)
	print "double round."
	c0 = encrypt(p0, 2, ksbox)
	c1 = encrypt(p1, 2, ksbox)
	print fmt(c0), fmt(c1)
	print "end diff:  ", diff(c0,c1)

if __name__ == '__main__':
	base_sbox = read_sbox()
	sbox = expand_sbox(base_sbox)
	key = gen_key()
	ksbox = keyed_sbox(sbox,key)
	print repr(ksbox.encode('hex')),len(set(ksbox)),len(ksbox)
	analysis('\x00\x00\x00','\x00\x00\x01', ksbox)
	analysis('\x00\x00\x08','\x00\x00\x09', ksbox)
	# hook(locals())