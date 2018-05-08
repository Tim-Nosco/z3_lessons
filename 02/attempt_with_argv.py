import angr, claripy
from string import printable
import logging
import subprocess

angrLogger = logging.getLogger()
angrLogger.setLevel(logging.INFO)

logger = logging.getLogger('solve5.py')
logging.basicConfig()
logger.setLevel(logging.INFO)


def hook():
	#for debugging
	import IPython
	IPython.embed()
	exit(0)

p = angr.Project('./count', auto_load_libs=False)
check_flag_char_addr = p.loader.find_symbol('check_flag_char').rebased_addr

def test_flag(flag):
	args = ['/home/tmnosco/Downloads/pin/pin', 
			'-t', '/home/tmnosco/Downloads/pin/inscount1.so', 
			'--', p.filename, flag]
	subprocess.call(args)

	with open("inscount.out", 'r') as f:
		data = f.read()

	x = 0
	try:
		x = int(data.split()[-1])
	except:
		pass	
	return x

flag = ""
for _ in range(0x2c):
	best = ('\0',0)
	total = 0
	for i, char in enumerate(printable):
		guess = (flag+char).ljust(0x2c,'a')
		current = test_flag(guess)
		best = (char,current) if current > best[1] else best
		total += current
		average = total/(i+1)
		logger.info("char: %s current: %s average: %s", char, current, average)
		if best[1] > average*1.01:
			break
	logger.info("best: %s", best)
	flag+= best[0]
	logger.info("flag: %s", flag)
