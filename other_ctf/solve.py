from subprocess import Popen, PIPE
import re
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


magic = (0xf7, 0x7b)
for i in range(10):
	weights = [0]*256
	m = 0
	numsamples = 0
	while numsamples<2000 or (m-magic[1])<ord('!'):
		s = ord(get_crypt(magic[0]-i)[i])
		weights[s]+=1
		if weights[s] > weights[m]:
			m = s
		numsamples+=1
	print repr(chr(m-magic[1]))