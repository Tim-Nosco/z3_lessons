import claripy, z3
import random

key = claripy.BVS('key',8)
res = claripy.BVS('res',8)
s = claripy.Solver()

table = random.sample(range(256), 256)

s.add(res==0x41)
print "looking for key where value is 0x41"
print "should be {}".format(table.index(0x41))

z3s = s._get_solver()
print "solver: {}".format(z3s)
z3key = claripy.backends.z3.convert(key)
z3res = claripy.backends.z3.convert(res)

f = z3.Function('f', z3.BitVecSort(8), z3.BitVecSort(8))
for i, e in enumerate(table):
	z3s.add(f(z3.BitVecVal(i,8))==z3.BitVecVal(e,8))
z3s.add(z3res==f(z3key))

print z3s.check()
m = z3s.model()
print "found: {}".format(m[z3key])
