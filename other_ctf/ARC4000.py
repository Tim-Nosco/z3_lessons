import os
from multiprocessing.dummy import Pool
from functools import partial
from threading import Lock

NUMCRYPT = 512
NUMSAMPLE= 100000

class atomic_ctr:
	def __init__(self):
		self.ctr = [0 for x in range(NUMCRYPT)]
		self.thread_lock = [Lock() for x in range(NUMCRYPT)]
	def inc(self, k):
		with self.thread_lock[k]:
			self.ctr[k] += 1
	def max(self):
		return max(enumerate(self.ctr), key=lambda e:e[1])

class ARC4000:
	def __init__(self, key):
		self.table = [x for x in range(256)]
		j = 0
		for i in range(256):
			j = (j + self.table[i] + key[i%len(key)])&0xff
			self.table[i], self.table[j] = self.table[j], self.table[i]
		self.i = 0
		self.j = 0

	def crypt(self, collect):
		for c in range(NUMCRYPT):
			self.i = (self.i+1)&0xff
			self.j = (self.i+self.table[self.i])&0xff
			self.table[self.i], self.table[self.j] = self.table[self.j], self.table[self.i]
			k = self.table[ (self.table[self.i]+self.table[self.j])&0xff ]//2
			collect[c].inc(k)

def run_arc(collect, i):
	key = map(ord,os.urandom(32))
	ARC4000(key).crypt(collect)

collect = [atomic_ctr() for i in range(NUMCRYPT)]
p = Pool(4)
p.map(partial(run_arc,collect), xrange(NUMSAMPLE))

collect = [x.max() for x in collect]
expected = NUMSAMPLE/float(NUMCRYPT)
collect = [(i, x[0],((x[1]-expected)/NUMSAMPLE)*100) for i,x in enumerate(collect)]
collect = sorted(collect, key=lambda e:e[2], reverse=True)
for e in collect[:16]:
	print "idx: %02x, byte:%02x, freq:%.2f%%" % e

import IPython
IPython.embed()