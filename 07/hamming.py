import angr

def hook():
	#for debugging
	import IPython
	IPython.embed()
	exit(0)

p = angr.Project('ffs')

