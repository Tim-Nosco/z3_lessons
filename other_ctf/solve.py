from subprocess import Popen, PIPE
import re
from threading import Lock
from functools import partial
from multiprocessing.dummy import Pool

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

def get_crypt(num_garbage_bytes):
	inp = "e\n{}\np\n".format('00'*num_garbage_bytes)
	with open('/dev/null', 'w') as f:
		p = Popen(['python3', 'ARC4000_orig.py'], stdin=PIPE, stdout=PIPE, stderr=f)
	o = p.communicate(inp)[0]

	m = re.findall(r"b'([0-9a-f]+)'", o)
	if m:
		return m[-1].decode('hex')

	print "NO MATCH"
	import IPython
	IPython.embed()

magic_table = """
idx: 3f9, byte:7c, freq:0.43%
idx: 3f5, byte:7a, freq:0.43%
idx: 3f3, byte:79, freq:0.42%
idx: 3dd, byte:6e, freq:0.41%
idx: 3ff, byte:7f, freq:0.41%
idx: 3df, byte:6f, freq:0.41%
idx: 3db, byte:6d, freq:0.41%
idx: 3f1, byte:78, freq:0.41%
idx: 3ef, byte:77, freq:0.41%
idx: 2eb, byte:75, freq:0.41%
idx: 337, byte:1b, freq:0.41%
idx: 2ed, byte:76, freq:0.41%
idx: 2ef, byte:77, freq:0.41%
idx: 2d9, byte:6c, freq:0.41%
idx: 3eb, byte:75, freq:0.41%
idx: 3c9, byte:64, freq:0.40%
"""
r = re.findall(r'idx: ([a-f0-9]+?), byte:([a-f0-9]+)', magic_table)
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