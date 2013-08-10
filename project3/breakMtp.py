#!/usr/bin/python

import base64
import binascii
import logging
import itertools
from itertools import izip
from itertools import cycle
import sys
import struct
import argparse
import string
import re

ALPHA = re.compile('[A-Za-z]')

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

def xor_ascii_hex(x,y):
    '''XOR two ASCII encoded hex bytes and return the hex encoded value.
    >>> xor_ascii_hex('0x68', '0x19')
    '0x71'
    '''
    return hex(int(x, 16) ^ int(y, 16))

def xor_hex_char(hex_x, chr_y):
    '''XOR hex encoded ascii with a char.
    >>> xor_hex_char('0x61', ' ')
    '0x41'
    '''
    return xor_ascii_hex(hex_x, hex(ord(chr_y)))

def xor_char_char(chr_x, chr_y):
    '''XOR a character with a character.
    >>> xor_char_char('b', ' ')
    '0x42'
    '''
    return hex(ord(chr_x) ^ ord(chr_y))

def byte2char(b):
    '''Utility to turn a hex encoded byte into a char
    >>> print byte2char('0x61')
    a
    '''
    return chr(int(b, 16))

def xor_lists(x,y):
    '''XOR two lists of hex encoded values and return the result.  Must be
    the same length (which they are for this project: 128 )
    >>> xor_lists(['0x00', '0x01', '0x00', '0x01'], ['0x00', '0x00', '0x01', '0x01'])
    ['0x0', '0x1', '0x1', '0x0']
    '''
    return [xor_ascii_hex(a,b) for a,b in zip(x,y)]

def hex2char(hex_list):
    '''Convert hex encoded to characters (some may not be printable)
    >>> hex2char(cipher2list('ct1.hex'))[1:9]
    ['k', 'm', '4', '8', 'c', 'G', 'K', 'X']
    '''
    return [chr(int(x, 16)) for x in hex_list]

def filter_non_printable(hex_string):
    return [x for x in hex_string if x in string.printable]

def slice_by(number):

    def slice_number(lst):
        return [lst[x:x+number] for x in range(0, len(lst), number)]

    return slice_number

def charToInt(char) :
    return ord(char)



def xorWithCrib(lst, cribText,startElem) :
    lstFromStartElem = lst[startElem:]
    cribIter = cycle(cribText)
    retLst = list()
    for elem in lstFromStartElem :
        currentCribChar = cribIter.next()
        xorVal = charToInt(currentCribChar) ^ elem
        retLst.append(xorVal)
    retLst = intListToAsciiList(retLst)
    return retLst

def intListToAsciiList(lst) :
    return [unichr(x) for x in lst]

def pp(lst):
    for index, char in zip(range(len(lst)), lst):
        print "Index: %s Char: %s" % (index, char)

def space_crack(cipher1, cipher2):
    '''Create two lists of possible keys using the space crack technique.
    >>> key1, key2 = space_crack(cipher2list('ct2.hex'), cipher2list('ct5.hex'))

    >>> key1[120]
    '0x5a'
    >>> key2[120]
    '0x38'
    '''
    key1 = make_key()
    key2 = make_key()

    xor = hex2char(xor_lists(cipher1, cipher2))

    for index, char in zip(range(len(cipher1)), xor):

        if ALPHA.match(char):

            char = string.swapcase(char)
            key1[index] = xor_hex_char(cipher1[index], char)
            key2[index] = xor_hex_char(cipher2[index], char)
        else:
            pass

    return key1, key2

def char2hex(char):
    return hex(ord(char))

def string2hex(my_string):
    return [char2hex(x) for x in my_string]

def is_alpha_or_space(s):
    matcher = re.compile('^[A-Za-z ]+$')

    if matcher.match(s):
        return True
    else:
        return False

def make_guesser(cipher1, cipher2):
    '''Return a function that returns a generator for guesses.
    >>> g = make_guesser(cipher2list('ct2.hex'), cipher2list('ct5.hex'))

    >>> x = g('The')

    >>> x.next()
    (['I', 'y', 'v'], 2)
    >>> x.next()
    (['E', 's', 'a'], 17)

    >>> x.next()
    (['L', 't', 'k'], 21)

    >>> x.next()
    (['O', 'r', 'e'], 43)

    >>> x.next()
    (['N', 'h', 'e'], 44)

    >>> x.next()
    (['T', 'h', 'e'], 45)
    '''

    def crib_xor(guess):
        '''Perform the guess

        '''
        hex_guess = string2hex(guess)

        log.debug(hex_guess)

        xored = xor_lists(cipher1, cipher2)

        for index in range(len(xored)):
            test_slice = xored[index:index+len(hex_guess)]

            result = xor_lists(hex_guess, test_slice)

            if is_alpha_or_space(''.join(hex2char(result))):

                yield hex2char(result), index

    return crib_xor

def guess_all(guesser):

    for word, index in guesser:
        print 'Index: %d Word: %s' % (index, ''.join(word))

def make_key():
    '''Make a list contained a null-ed out key.
    >>> make_key()[0:4]
    ['0x00', '0x00', '0x00', '0x00']
    '''
    key = list()
    for x in range(128):
        key.append('0x00')
    return key


if __name__=="__main__":
    import doctest
    doctest.testmod()

    parser = argparse.ArgumentParser(description='Xor cracker')
    parser.add_argument('cribText', help='The crib text')
    parser.add_argument('findText', help='The text to find')

    args = parser.parse_args()

    cipherDict = make_cipher_dict(files)
    xorResults = list()

    for key1 in cipherDict :
        for key2 in cipherDict :
            if(key1 != key2) :
                log.debug("Test with: "+key1+"and "+key2)
                xorResult = hex2char(xor_lists(cipherDict[key1],cipherDict[key2]))
                xorResults.append(xorResult)
                log.debug(xorResult)

    # Try to find cribtext in any of the xor'd files
    decodeResults = list()

    for xorResult in xorResults :
        decodeResult = xorWithCrib(xorResult,args.cribText,0)
        decodeResults.append(decodeResult)
