import os

BLOCK_SIZE = 12

def hook(l=None):
	if l:
		locals().update(l)
	import IPython
	IPython.embed(banner1="",confirm_exit=False)
	exit()

def b642ints(str_seq):
	b64_alpha='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	k = dict((x,i) for i,x in enumerate(b64_alpha))
	return [k[x] for x in str_seq]	

def read_sbox():
	with open('save.txt','r') as f:
		data = f.read()
	return [b642ints(line) for line in data.split()]

def gen_key():
	return int(os.urandom(BLOCK_SIZE).encode('hex'),16)

def sub(m,sbox):
	mask = (1<<6)-1
	return reduce(lambda a,x: a|(sbox[(m>>x)&mask]<<x), range(0,BLOCK_SIZE*8,6), 0)

def split_words(m):
	mask = 0xFFFFFFFF
	r0 = (m>>0) &mask
	r1 = (m>>32)&mask
	r2 = (m>>64)&mask
	return r0,r1,r2

def join_words(r0,r1,r2):
	m = 0
	m |= r0 << 0
	m |= r1 << 32
	m |= r2 << 64
	return m

def ror(val, r_bits, max_bits):
	return ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
		(val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def expand_key(k):
	yield k
	mask = 0xFFFFFFFF
	while True:
		r0,r1,r2 = split_words(k)
		r0 = ror(r0, 3, 32)
		r0 = (r0 + r1) & mask
		r1 = ror(r1, 7, 32)
		r2 = r2 ^ r1
		r2 = (r2 + r0) & mask
		r1 = r1 ^ r0
		k = join_words(r0,r1,r2)
		yield k

def bit_mix(m):
	mask = 0xFFFFFFFF
	r0,r1,r2 = split_words(m)
	r2 = r2 ^ r1
	r1 = (r1 + r0) & mask
	r0 = ror(r0, 5, 32)
	r2 = (r2 + r0) & mask
	r0 = r0 ^ r1
	return join_words(r0,r1,r2)

def encrypt_round(m, key, round_num, sbox):
	c0 = key ^ m
	c1 = sub(c0,sbox[round_num%len(sbox)])
	c2 = bit_mix(c1)
	return c2

def encrypt(m, key, rounds):
	sbox = read_sbox()
	key = expand_key(key)
	ct = int(m.encode('hex'),16)
	for i in range(rounds):
		ct = encrypt_round(ct, key.next(), i, sbox)
	ct_asx = hex(ct)[2:].replace('L','')
	ct_asx = ct_asx.zfill((len(ct_asx)+1)//2*2)
	return ct_asx.decode('hex')

def analysis(p0,p1,key,rounds=3):
	def fmt(x, style='base64'): return x.rjust(BLOCK_SIZE,'\x00').encode(style).strip()
	def diff(x,y,style='base64'): 
		return hex(int(x.encode('hex'),16)^int(y.encode('hex'),16))[2:]\
				.replace('L',"").zfill(BLOCK_SIZE*2).decode('hex').encode(style).strip()
	print "--------"
	print "start vals:", fmt(p0), fmt(p1)
	c0 = encrypt(p0,key,rounds)
	c1 = encrypt(p1,key,rounds)
	print "end vals:  ",fmt(c0), fmt(c1)
	print "start diff:", diff(p0,p1)
	print "end diff:  ", diff(c0,c1)

if __name__ == '__main__':
	key = gen_key()
	analysis('\x00','\x01', key)
	analysis('\x08','\x09', key)
	# hook(locals())