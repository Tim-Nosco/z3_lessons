import random

BITS = 32

def rotate(l,n):
    #https://stackoverflow.com/questions/9457832/python-list-rotation
    return l[n:] + l[:n]

def merge(upper, lower):
    return [(u<<4)|l for u,l in zip(upper,lower)]

def split(k):
    lower = []
    upper = []
    for b in k:
        lower.append(b&0xf)
        upper.append((b&0xf0)>>4)
    return upper,lower

def key_expand(k0):
    keys = k0
    u, l = split(k0)
    for _ in range(1,16):
        u,l = rotate(u,3), rotate(l,7)
        keys += merge(u,l)
    if len(set(keys))!=len(keys):
        diff = len(set(keys)), len(keys)
        raise Exception("Invalid sbox. %d unique values of %d."%diff)
    return keys

def gen_key():
    #todo: figure out safe random sample
    u = random.sample(range(16),16)
    l = random.sample(range(16),16)
    return merge(u,l)

def substitute(x,sbox):
    collect = 0
    for i in range(0,BITS,8):
        xi = (x>>i)&0xff
        yi = sbox[xi]
        collect |= yi<<i
    return collect

def round(x,sbox):
    #todo: fix invertability
    m0 = int("a"*(BITS/4),16)
    m1 = int("5"*(BITS/4),16)
    a = x&m0
    b = (x<<1)&m0
    c = (a&b)|m1
    d = c+x
    return substitute(d,sbox)

def encrypt(pt, key):
    sbox = key_expand(key)
    x = int(pt.encode('hex'),16)
    #todo: test with more rounds
    for _ in range(4):
        x = round(x,sbox)
    return x

def log_crypt(pt,key):
    print "pt: {}".format(pt.encode('hex'))
    ct = encrypt(pt,key)
    print "ct: {}".format(hex(ct)[2:].replace('L',''))
    return ct

def test():
    key = gen_key()
    print "key: {}".format(''.join('%02x'%k for k in key))
    x0 = log_crypt("TEST",key)
    x1 = log_crypt("TESU",key)
    print "d:  %08x" % (x0^x1)

if __name__ == '__main__':
    test()

"""
Currently possible to get this example (occurs likely?)
Need to ensure x0!=x1 -> E(x0)!=E(x1)
This CE implies non-invertable

key: 983eea1d7069f157a44bd322b60f85cc
pt: 54455354
ct: ea1cea6f
pt: 54455355
ct: ea1cea6f
d:  00000000
"""