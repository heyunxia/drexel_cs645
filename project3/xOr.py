#!/usr/bin/python

import base64
import binascii
import logging
from itertools import izip
import sys
import struct
import argparse
import string

logging.basicConfig(
    format = "%(levelname)-5s %(module)s.py: line %(lineno)d: %(message)s",
    level  = logging.DEBUG
)

ONE = 'ct1.hex'
TWO = 'ct2.hex'
THREE = 'ct3.hex'
FOUR = 'ct4.hex'
FIVE = 'ct5.hex'
SIX = 'ct6.hex'
SPACE = ' '

log = logging.getLogger('xor')

files = list()

testMode = False

if(testMode) :
    files = ["testTxt1","testTxt2"]
else :
    files = [ONE, TWO, THREE, FOUR, FIVE, SIX]

def cipher2list(cipher_file_name):
    '''Load in the cipher text and return a list of ASCII encoded hex bytes
    >>> print cipher2list('ct1.hex')[1:10]
    ['0x6b', '0x6d', '0x34', '0x38', '0x63', '0x47', '0x4b', '0x58', '0x1f']
    '''
    with open(cipher_file_name) as f:
        return f.read().split()

def make_cipher_dict(list_of_files):
    '''Give a list of files, return a dict whose key is the filename and
    whose value is a list of ASCII encoded bytes
    >>> print make_cipher_dict(['ct1.hex'])['ct1.hex'][0:9]
    ['0x17', '0x6b', '0x6d', '0x34', '0x38', '0x63', '0x47', '0x4b', '0x58']
    '''
    ciphers = {}
    for l in list_of_files:
        ciphers[l] = cipher2list(l)

    return ciphers

ciphertexts = make_cipher_dict(files)

# Example xor
outAsHex = False
outAsAscii = False

# Tracks the names of the ciphertexts that were xored togethed
xorOutputFileNames = []

# Trackes the decode attempts
decodeAttemptFileNames = []

def xor_hex(x,y):
    '''XOR two ASCII encoded hex bytes and return the hex encoded value.
    >>> xor_hex('0x68', '0x19')
    '0x71'
    '''
    return hex(int(x, 16) ^ int(y, 16))

def xor_hex_chr(hex_x, chr_y):
    '''XOR hex encoded ascii with a char.
    >>> xor_hex_chr('0x61', ' ')
    '0x41'
    '''
    return xor_hex(hex_x, hex(ord(chr_y)))

def xor_lists(x,y):
    '''XOR two lists of hex encoded values and return the result.  Must be
    the same length (which they are for this project: 128 )
    >>> xor_lists(['0x00', '0x01', '0x00', '0x01'], ['0x00', '0x00', '0x01', '0x01'])
    ['0x0', '0x1', '0x1', '0x0']
    '''
    return [xor_hex(a,b) for a,b in zip(x,y)]

def hex2char(hex_list):
    '''Convert hex encoded to characters (some may not be printable)
    >>> hex2char(cipher2list('ct1.hex'))[1:9]
    ['k', 'm', '4', '8', 'c', 'G', 'K', 'X']
    '''
    return [chr(int(x, 16)) for x in hex_list]

def filter_non_printable(hex_string):
    return [x for x in hex_string if x in string.printable]


def pp_list(lst):
    LENGTH = 12

    for x in range( len(lst) / LENGTH ):
        start = x*LENGTH
        print ''.join(str(lst[start:start+LENGTH]))

def writeToFile(fileHandle,xorVal) :
    packedString = struct.pack('B',xorVal)
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
                #xorWithCribText(xorOutFileName,cribText,offset)


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
