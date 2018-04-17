import angr, claripy, archinfo
import logging
from struct import unpack, pack
import subprocess

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def chunks(l, n):
	#(list[int],int) -> list[list[int]]
	for i in range(0,len(l),n):
		yield l[i:i+n]

def hook():
	#for debugging
	import IPython
	IPython.embed()
	exit(0)

p = angr.Project("./philosophersstone", auto_load_libs=False)

decrypt_addr = 	0x80484bb
decrypt_end = 	0x8048506
flag_buf_addr = 0x8049b44
secret_addr = 	0x8049ac0
output_buf =	0x8049b20
s = p.factory.blank_state(addr=decrypt_addr)

#ensure the input location is symbolic
flag = [claripy.BVS("x{}".format(i),8*4) for i in range(4)]
for i,x in enumerate(flag):
	s.memory.store(flag_buf_addr+4*i, x)

sm = p.factory.simgr(s)
logger.info("Starting Explore...")
logger.info(sm.explore(find=decrypt_end))

for path in sm.found:
	#get the encrypted flag
	enc = [path.mem[flag_buf_addr+4*i].uint32_t.resolved for i in range(4)]
	#break up the secret string into ints
	target = chunks(path.mem[secret_addr].string.concrete.decode('hex'),4)
	#Optional: target = [unpack(">I",x)[0]for x in target]
	#ensure the output equals the secret values
	path.add_constraints(*[x==y for x,y in zip(enc, target)])
	#evaluate each input integer
	fp = [pack("<I",path.solver.eval(x)) for x in flag]
	#join the bytes together as hex
	fp = ''.join(fp).encode('hex')
	#print the flag
	logger.info("FLAG: %s", fp)

	#test it out
	argv = [p.filename,fp]
	logger.info("RUNNING: %s", ' '.join(argv))
	logger.info(subprocess.check_output(argv))