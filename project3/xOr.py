import base64
import binascii
from itertools import izip

files = ["ct1.hex","ct2.hex","ct3.hex","ct4.hex","ct5.hex","ct6.hex"]

# Example xor
outAsHex = True
outAsAscii = False

def calcXor(keyFile,cipherFile,xorOut) :
    xorOut = open("ct1out.hex",'wb')
    for k, c in zip(keyFile,cipherFile) :
        k = k.strip()
        c = c.strip()
        kInt = int(k,16)
        cInt = int(c,16)
        xorVal = hex(kInt ^ cInt)
        if(outAsHex) :
            print xorVal
        elif(outAsAscii) :
            print chr(kInt ^ cInt)
        xorOut.write(xorVal)

for cipherFileName in files :
    for keyFileName in files :
        keyFile = open(keyFileName,'rb')
        cipherFile = open(cipherFileName,'rb')
        xorOut = open(keyFileName+cipherFileName+".xor",'wb')
        calcXor(keyFile,cipherFile,xorOut)
