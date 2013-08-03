#!/usr/bin/python

import base64
import binascii
import logging
from itertools import izip
import sys

logger = logging.getLogger('xOr')
logger.setLevel(logging.INFO)
files = ["ct1.hex","ct2.hex","ct3.hex","ct4.hex","ct5.hex","ct6.hex"]

keyFileName = files[0]
cipherFileName = files[5]

# Example xor
outAsHex = False
outAsAscii = True
xorWithSpace = False

# Tracks the names of the ciphertexts that were xored togethed
xorOutputFileNames = []

def calcXor(keyFile,cipherFile,xorOut) :
    for k, c in zip(keyFile,cipherFile) :
        k = k.strip()
        c = c.strip()
        kInt = int(k,16)
        cInt = int(c,16)
        if(outAsHex) :
            xorVal = hex(kInt ^ cInt)
            logger.debug(xorVal)
            xorOut.write(xorVal)
        elif(outAsAscii) :
            xorVal = kInt ^ cInt
            spaceVal = int(ord(' '))
            if(xorWithSpace) :
                xOrWithSpaceVal = xorVal ^ spaceVal
                xOrVal = xOrWithSpaceVal
                logger.debug("With space is: %s" % str(xOrVal))
                asString = str(unichr(xOrVal))
                logger.debug("With space is string is: %s" % asString)
                xorOut.write(asString)
            else :
                xorVal = str(unichr(kInt ^ cInt))
                xorOut.write(xorVal)
            logger.debug(xorVal)

def xorWithCribText(xorFileName,cribText,offset) :
    cribLen = len(cribText)
    cribIdx = 0
    xorFile = open(xorFileName,'rb')
    linesAfterOffset = xorFile.readlines()[offset:]
    for l in linesAfterOffset :
        l = l.strip()
        lInt = int(l,16)
        cribInt = int(cribText[cribIdx],16)
        xorVal = lInt ^ cribInt
        xorValAsString = str(unichr(xorVal))
        logger.debug(xorValAsString)
    cribLen = len(cribText)
    cribIdx = 0
    for l in xorFile :
        l = l.strip()
        lInt = int(l,16)
        cribInt = int(cribText[cribIdx],16)
        xorVal = lInt ^ cribInt
        xorValAsString = str(unichr(xorVal))
        logger.debug(xorValAsString)

def tryToDecodeAll(cribText,offset) :
    for cipherFileName in files :
        for keyFileName in files :
            keyFile = open(keyFileName,'rb')
            cipherFile = open(cipherFileName,'rb')
            xorOutFileName = keyFileName+cipherFileName+".xor"
            xorOutputFileNames.append(xorOutFileName)
            xorOut = open(xorOutFileName,'wb')
            calcXor(keyFile,cipherFile,xorOut)
            xorWithCribText(xorOutFileName,cribText,offset)

def xorTwoFiles(keyFileName,cipherFileName) :
    keyFile = open(keyFileName,'rb')
    cipherFile = open(cipherFileName,'rb')
    xorOut = open(keyFileName+cipherFileName+".xor",'wb')
    # Xor two texts
    calcXor(keyFile,cipherFile,xorOut)

# Get the crib text
cribText = sys.argv[1]
# Try to find the 'findtext'
findText = sys.argv[2]
# Get the offset
for offset in xrange(0,len(cribText)) :
    # Decode all file
    tryToDecodeAll(cribText,offset)

    for fileName in xorOutputFileNames :
        with open(fileName,'r') as f :
            read_data = f.read()
            if findText in read_data :
                print "Match on : "+str(findText)+" in: "+fileName
