import angr, claripy
import logging
from string import letters, digits, punctuation
all_chars = map(ord,letters+digits+punctuation)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

p = angr.Project("./count")
s = claripy.Solver()
start = p.factory.entry_state()

f = p.factory.callable(0x080484bb)
hash_len = 0x20
var_len = 4
fin = claripy.BVS('sym_arg', 8*hash_len)
fixed = '\0'*(hash_len-var_len)
s.add(fin.get_bytes(var_len, hash_len-var_len)==fixed)
var_chr = fin.get_bytes(0,1)
s.add(var_chr >= min(all_chars))
s.add(var_chr <= max(all_chars))

res = f(fin, hash_len)

flag = ""
for i in range(44):
	tmp=[]
	tmp.append(res==start.mem[0x08049a00+4*i].long.concrete)
	tmp.append(fin.get_bytes(1,var_len)=="-{}".format(hex(i)[2:]).ljust(var_len,'\0'))
	e = s.eval(fin.get_bytes(0,1),1,extra_constraints=tmp)[0]
	logger.info("FOUND: %s", e)
	try:
		flag += chr(e)
		logger.info("-> %s", flag)
	except:
		pass