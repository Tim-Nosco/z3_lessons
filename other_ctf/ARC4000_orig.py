#!/usr/bin/python3 -u
import os
from binascii import hexlify, unhexlify

flag = open("./flag.txt","rb").read()

class ARC4000(object):
 def __init__(self, key):
   self.table = [x for x in range(256)]
   j = 0
   for i in range(256):
     j = (j + self.table[i] + key[i%len(key)])&0xff
     self.table[i], self.table[j] = self.table[j], self.table[i]
   self.i = 0
   self.j = 0

 def crypt(self, string):
   out = []
   for c in string:
     self.i = (self.i+1)&0xff
     self.j = (self.i+self.table[self.i])&0xff
     self.table[self.i], self.table[self.j] = self.table[self.j], self.table[self.i]
     k = self.table[ (self.table[self.i]+self.table[self.j])&0xff ]//2
     out.append((c+k)&0xff)
   return bytearray(out)


cipher = ARC4000(os.urandom(32))

while True:
 print("Commands: (e)ncrypt msg or (p)rint encrypted flag")
 choice = input("Choose command: ")

 if choice == 'e':
   message = input("What is your message (hex encoded)? ")
   print(hexlify(cipher.crypt(unhexlify(message))))
 elif choice == 'p':
   print(hexlify(cipher.crypt(flag)))
 else:
   print("Invalid choice!")