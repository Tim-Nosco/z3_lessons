import z3
MAXBITS = 3
MAXVAL = 2**MAXBITS

def b642ints(str_seq):
	b64_alpha='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	k = dict((x,i) for i,x in enumerate(b64_alpha))
	return [k[x] for x in str_seq]	
def ints2b64(seq_of_ints):
	a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	return ''.join(a[x] for x in seq_of_ints)

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
	return ints2b64(new_sbox)

def main():
	with open("save.txt","r") as f:
		data = f.read()
	sboxes = map(b642ints, data.split()[:3])
	new_sboxes = map(keyed_sbox,sboxes)
	for o,n in zip(sboxes,new_sboxes):
		print "old:",o
		print "new:",n

if __name__ == '__main__':
	main()