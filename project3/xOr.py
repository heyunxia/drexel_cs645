#!/usr/bin/python

import base64
import binascii
import logging
from itertools import izip
import sys
import struct
import argparse

logging.basicConfig(
    format = "%(levelname)-5s %(module)s.py: line %(lineno)d: %(message)s",
    level  = logging.DEBUG
)

log = logging.getLogger('xor')

files = list()

testMode = False

if(testMode) :
    files = ["testTxt1","testTxt2"]
else :
    files = ["ct1.hex","ct2.hex","ct3.hex","ct4.hex","ct5.hex","ct6.hex"]

# Example xor
outAsHex = False
outAsAscii = False

# Tracks the names of the ciphertexts that were xored togethed
xorOutputFileNames = []

# Trackes the decode attempts
decodeAttemptFileNames = []

def xor_ascii_hex(x,y):
    '''XOR two ASCII encoded hex bytes and return the hex encoded value.
    >>> xor_ascii_hex('0x68', '0x19')
    '0x71'
    '''
    return hex(int(x, 16) ^ int(y, 16))

def writeToFile(fileHandle,xorVal) :
    packedString = struct.pack('B',xorVal);
    fileHandle.write(packedString)

def xorBytesRepresentedAsStrings(fileHandle,char1,char2) :
    char1 = char1.strip()
    char2 = char2.strip()
    # print("Xoring: %s and %s" % (char1,char2))
    char1Int = int(char1,16)
    char2Int = int(char2,16)
    xorVal = char1Int ^ char2Int
    # print "Get result: %x " % xorVal
    writeToFile(fileHandle, xorVal)
    log.debug(xorVal)

def calcXor(keyFile,cipherFile,xorOut) :
    for k, c in zip(keyFile,cipherFile) :
        xorBytesRepresentedAsStrings(xorOut,k,c)

def xorWithCribText(xorFileName,cribText,offset) :
    decodeAttemptFileName = xorFileName+cribText+str(offset)
    decodeAttemptFileNames.append(decodeAttemptFileName)


    with open(decodeAttemptFileName,'wb') as decodeFile :
        cribLen = len(cribText)
        cribCount = 0
        xorFile = open(xorFileName,'rb')
        # First, advance 'offset' number of bytes
        xorFile.read(offset)
        # Then apply the cribtext to the rest of the file
        readByte = xorFile.read(1)
        while(readByte != "") :
            cribChar = None
            if(cribLen == 1) :
                cribChar = cribText[0]
            else :
                cribChar = cribText[cribCount % cribLen]
#            print "cribChar is: "+cribChar
            cribInt = ord(cribChar)
#            print "cribInt is: "+str(cribInt)
            (readByteUnpacked,) = struct.unpack('B',readByte)

            xorVal = cribInt ^ readByteUnpacked
            writeToFile(decodeFile,xorVal)

            # Increment crib counter and write new byte
            cribCount = cribCount + 1
            readByte = xorFile.read(1)

def tryToDecodeAll(cribText,offset) :
    for cipherFileName in files :
        for keyFileName in files :
            if(keyFileName != cipherFileName) :
                keyFile = open(keyFileName,'rb')
                cipherFile = open(cipherFileName,'rb')
                xorOutFileName = keyFileName+cipherFileName+".xor"
                xorOutputFileNames.append(xorOutFileName)
                xorOut = open(xorOutFileName,'wb')
                calcXor(keyFile,cipherFile,xorOut)
                xorOut.close()
                xorWithCribText(xorOutFileName,cribText,offset)


if __name__=="__main__":
    import doctest
    doctest.testmod()

    parser = argparse.ArgumentParser(description='Xor cracker')
    parser.add_argument('cribText', help='The crib text')
    parser.add_argument('findText', help='The text to find')

    args = parser.parse_args()

    # Get the offset
    for offset in xrange(0,len(args.cribText)) :
        # Create decode outputs for the cribtext on a range of offsets
        tryToDecodeAll(args.cribText,offset)

        # Try to find the searchtext in the output
        for fileName in decodeAttemptFileNames :
            with open(fileName,'r') as f :
                read_data = f.read()
                if args.findText in read_data :
                    log.info("Match on : "+str(args.cribText)+" and "
                             +str(args.findText)+" in: "+fileName)
