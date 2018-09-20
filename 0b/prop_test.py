import z3
def propigate_old(m,key_bit):
	bmask = (1<<(3*8))-1
	ml = m
	hmask = int('01'*bmask.bit_length(),2)
	v0 = ml&hmask
	v1 = (ml>>1)&hmask
	v2 = v0^v1
	v3 = (v0&v1)<<1
	v4 = v2|v3
	v5 = z3.If(key_bit==1,v4^bmask,v4)
	v6 = (v5+ml)&bmask
	return v6

def ror(val, r_bits, max_bits):
	return ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
		(val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def swap(l,i,j):
	t = l[i]
	l[i]=l[j]
	l[j]=t

def propigate(message,key_bit):
	m = (1<<6)-1
	p = [(message>>(6*i))&m for i in range(4)]
	p[0]=ror(p[0], 1, 6)
	p[0]=z3.If(key_bit==1,p[0],p[0]^m)
	p[1]=z3.If(key_bit==1,ror(p[1], 1, 6), ror(p[1], 5, 6))
	p[1]=p[1]^p[2]
	p[2]=p[2]^p[0]
	p[0]=(p[0]+p[1])&m
	p[3]=p[3]^p[0]
	swap(p,0,2)
	swap(p,2,3)
	swap(p,1,3)
	return reduce(lambda a,x:a|(p[x]<<(6*x)), range(4), 0)

if __name__ == '__main__':
	a,b = z3.BitVecs('a b',3*8)
	k = z3.BitVec('k',1)
	z3.prove(z3.ForAll([a,b,k], z3.Implies(a!=b,
			propigate(a,k)!=propigate(b,k))))
