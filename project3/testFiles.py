#!/usr/bin/env python
from otp import *
from array import array
print "Test"

oneTimePad = OneTimePad()
fileNames = ["ct1.hex","ct2.hex","ct3.hex","ct4.hex","ct5.hex","ct6.hex"]
for name in fileNames :
    print name

for ciphertext in fileNames :
    for otp in fileNames :
        cipherFile = open(ciphertext,'rb')
        keyFile = open(otp,'r')
        outputName = str(ciphertext)+str(otp)+"deciphered"
        print "Writing: "+str(outputName)
        outputFile = open(outputName,'wb')
        oneTimePad.cipher(cipherFile,outputFile,keyFile)
        outputRead = open(outputName,'rb')
        outputText = outputRead.read() 
        print outputText.decode('hex')
            
        #data = array('c')
        #CHUNKSIZE = 8192
        #rowcount = CHUNKSIZE / data.itemsize  # number of doubles we find in CHUNKSIZE bytes

        #with open(outputName, 'rb') as eg:
        #    data.fromfile(eg, rowcount)
        #    print data

