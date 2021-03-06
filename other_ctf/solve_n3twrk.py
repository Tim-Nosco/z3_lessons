from subprocess import Popen, PIPE
import re
from threading import Lock
from functools import partial
from multiprocessing.dummy import Pool
import pwn

NUMCRYPT = 0x100

class atomic_ctr:
	def __init__(self):
		self.ctr = [0 for x in range(NUMCRYPT)]
		self.thread_lock = [Lock() for x in range(NUMCRYPT)]
	def inc(self, k, v=1):
		with self.thread_lock[k]:
			self.ctr[k] += v
	def max(self):
		return max(enumerate(self.ctr), key=lambda e:e[1])

def network(inp):
	p = pwn.remote("challenges.acictf.com", 43434)
	p.recvuntil('flag')
	p.send('e\n{}\n'.format(inp))
	p.recvuntil('flag')
	p.send('p\n')
	r = p.recvuntil('flag')
	p.close()
	return r

def get_crypt(num_garbage_bytes):
	o = network('00'*num_garbage_bytes)

	m = re.findall(r"b'([0-9a-f]+)'", o)
	if m:
		return m[-1].decode('hex')

	print "NO MATCH"
	import IPython
	IPython.embed()



magic = (0x5dd, 0x6e)

def single_run(weights, i, idx):
	s = ord(get_crypt(magic[0]-i)[i])
	weights.inc(s)

p = Pool(4)
for i in range(33):
	weights = atomic_ctr()
	p.map(partial(single_run, weights, i), xrange(10000))
	sorted_weights = sorted(enumerate(weights.ctr), key=lambda e: e[1], reverse=True)
	multv = [(chr(i-magic[1]), x) for i,x in sorted_weights if i-magic[1]>0 ]
	vl = multv[:8]
	v = vl[0]
	with open('log.txt', 'a') as f:
		f.write("{}\n{}\n".format(repr(v),repr(vl)))
