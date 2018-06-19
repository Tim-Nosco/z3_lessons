import os
from multiprocessing.dummy import Pool
from functools import partial
from threading import Lock
from subprocess import check_output
import re

NUMCRYPT = 4096
NUMSAMPLE= 2000000

class atomic_ctr:
	def __init__(self):
		self.ctr = [0 for x in range(NUMCRYPT)]
		self.thread_lock = [Lock() for x in range(NUMCRYPT)]
	def inc(self, k, v=1):
		with self.thread_lock[k]:
			self.ctr[k] += v
	def max(self):
		return max(enumerate(self.ctr), key=lambda e:e[1])

def run_arc(collect, i):
	key = int(os.urandom(15).encode('hex'),16)
	args = ['./rc4', str(key), str(NUMCRYPT), str(i)]
	o = check_output(args)
	m = re.findall(r'POSITION: ([0-9a-f]+)?\n([0-9a-f ]+?)\n', o)
	for i1, l in m:
		for i2, v in enumerate(l.split()):
			collect[int(i1,16)].inc(i2, int(v,16))

collect = [atomic_ctr() for i in range(NUMCRYPT)]
p = Pool(4)
p.map(partial(run_arc,collect), [NUMSAMPLE/4]*4)

collect = [x.max() for x in collect]
expected = NUMSAMPLE/float(0x80)
collect = [(i, x[0],((x[1]-expected)/NUMSAMPLE)*100) for i,x in enumerate(collect)]
collect = sorted(collect, key=lambda e:e[2], reverse=True)
for e in collect[:16]:
	print "idx: %02x, byte:%02x, freq:%.2f%%" % e

import IPython
IPython.embed()