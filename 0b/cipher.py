from base64 import b64encode, b64decode
from random import sample,randint

MAXBITS= 3
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

def b64_alpha():
	# b = "\x00\x00"
	# return reduce(lambda a,x: a+b64encode(b+chr(x))[-1], 
	# 							range(2**(MAXBITS*2)), "")
	return 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def b64_ints2b64(seq_of_ints):
	a = b64_alpha()
	return ''.join(a[x] for x in seq_of_ints)

def b64_b642ints(str_seq):
	k = dict((x,i) for i,x in enumerate(b64_alpha()))
	return [k[x] for x in str_seq]	

def read_sbox():
	with open('save.txt','r') as f:
		data = f.read()
	return map(ord, data.decode('hex'))

def gen_key():
	"""
	The key is MAXVAL many elements which consist of unique upper halves
		and lower halves.
	"""
	c = range(MAXVAL)
	u = sample(c,MAXVAL)
	l = sample(c,MAXVAL)
	return [(x<<MAXBITS)|y for x,y in zip(u,l)], randint(0,2**(2*MAXBITS))

def keyed_sbox(sbox,key):
	"""
	sbox: list[int]
		This is the original bnum3 sbox loaded in as a list of ints
	key: list[int]
		This key has special properties, should be generated like in gen_key
	return: str
		The return is a new sbox, formatted as a b64 string
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
	return b64_ints2b64(new_sbox)

def sub(m,sbox):
	"""
	m: str
		a raw string to be substituted.
	sbox: str
		a b64 encoded sbox (such as the output of keyed_sbox)
	"""
	k = dict(zip(b64_alpha(),sbox))
	return ''.join(k.get(x,'=') for x in b64encode(m)).decode('base64')

def propigate(m,key_bit):
	bmask = (1<<(len(m)*8))-1
	ml = int(m.encode('hex'),16)
	hmask = int('01'*bmask.bit_length(),2)
	v0 = ml&hmask
	v1 = (ml>>1)&hmask
	v2 = v0^v1
	v3 = (v0&v1)<<1
	v4 = v2|v3
	v5 = v4^bmask if key_bit else v4
	print bin(v5)[2:].zfill(bmask.bit_length())
	v6 = (v5+ml)&bmask
	return hex(v6)[2:].replace('L','').zfill(len(m)*2).decode('hex')

def encrypt_round(m, key, round_num, sbox):
	c0 = sub(m,sbox)
	c1 = propigate(c0, ror(key,round_num,MAXBITS*2)&1)
	return c1

def analysis(p0,p1,kbits,ksbox):
	def fmt(x): return x.encode('hex').zfill(6)
	def diff(x,y): return hex(int(fmt(x),16)^int(fmt(y),16))[2:].replace('L',"").zfill(6)
	print fmt(p0), fmt(p1)
	c0 = encrypt_round(p0, kbits, 0, ksbox)
	c1 = encrypt_round(p1, kbits, 0, ksbox)
	print fmt(c0), fmt(c1)
	print "start diff:", diff(p0,p1)
	print "end diff:  ", diff(c0,c1)

if __name__ == '__main__':
	sbox = read_sbox()
	key,kbits = gen_key()
	ksbox = keyed_sbox(sbox,key)
	analysis('\x00\x00\x00','\x00\x00\x01', kbits, ksbox)
	analysis('\x00\x00\x08','\x00\x00\x09', kbits, ksbox)
	# hook(locals())