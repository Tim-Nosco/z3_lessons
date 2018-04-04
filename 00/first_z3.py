from z3 import *

s = Solver()

x = Int("x")
y = Int("y")

# does there exist an x such that
# 3*x = 6

s.add(3*x==6)

print s.check()
print s.model()


s2 = Solver()

s2.add(x*2 == y*3)

print s2.check()
print s2.model()

s3 = Solver()

s3.add(x*2==3)

print s3.check()