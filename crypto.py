from __future__ import division
import binascii
import string
import base64
import collections
import math
import string
'''
#Problem 1, Converting hex to base64
def hexToBase64(s):
	decoded = binascii.unhexlify(s)
	return base64.b64encode(decoded).decode('ascii')

x = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
y = hexToBase64(x)
#print(y)
'''

#------------------------------------------------------------------------------
#Problem 2,
def encrypt(plaintext, key):

	ciphertext = []
	for i in xrange(0, len(plaintext)):
		ciphertext.append(ord(plaintext[i]) ^ ord(key[i % len(key)]))

	return ''.join(map(chr, ciphertext))

decrypt = encrypt
#print "746865206b696420646f6e277420706c6179".decode('hex')
#print decrypt("1c0111001f010100061a024b53535009181c".decode('hex'), "686974207468652062756c6c277320657965".decode('hex'))


#-----------------------------------------------------------------------------
#Problem 3, single byte XOR, my answer

'''
def is_ascii(s):
	return all(c in string.printable for c in s)

key = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

for j in xrange(0, 255):
	if is_ascii(encrypt(key.decode('hex'), chr(j))):
		print(encrypt(key.decode('hex'), chr(j))+", "+chr(j))
	j=j+1

#Problem 3, other solution
'''


english_letter_frequency = collections.defaultdict(int, {
    ' ': .1217,
    'a': .0609,
    'b': .0105,
    'c': .0284,
    'd': .0292,
    'e': .1136,
    'f': .0179,
    'g': .0138,
    'h': .0341,
    'i': .0544,
    'j': .0024,
    'k': .0041,
    'l': .0292,
    'm': .0276,
    'n': .0544,
    'o': .0600,
    'p': .0195,
    'q': .0024,
    'r': .0495,
    's': .0568,
    't': .0803,
    'u': .0243,
    'v': .0097,
    'w': .0138,
    'x': .0024,
    'y': .0130,
    'z': .0003,
    '_': .0657,
})

def recover_xor_key(cipher_text):
    xor_text_map = {
        char: single_byte_xor(cipher_text, char) for char in string.printable
    }

    scores = {
        char: score_text(text) for char, text in xor_text_map.items()
    }

    key = min(scores, key = scores.get)

    return (key, scores[key], xor_text_map[key])

def single_byte_xor(string, character):
    return ''.join([chr(ord(a) ^ ord(character)) for a in string])

def score_text(text):
    counter = collections.Counter([
        char.lower() if char not in string.punctuation else '_'
        for char in text
    ])

    total = len(text)

    return sum([
        math.pow(abs(english_letter_frequency[char] - (count / total)), 2)
        if char in string.printable else 1
        for char, count in counter.items()
    ])

#------------------------------------------------------------------------------
#Problem 4, multiple character strings encoded in a one byte XOR, my solution

'''
i = 0
j = 0
f = open("f.txt")

while(i<256):
	j=0
	key = f.readline()
	key = key[0:-1]
	while (j < 256):
		if is_ascii(encrypt(key.decode('hex'), chr(j))):
			print(encrypt(key.decode('hex'), chr(j))+", "+chr(j)+", "+str(i))
		j=j+1
	i=i+1
'''
'''
#-------------------------------------------------------------------------------------
#Problem 5, encrypting

def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    
    return reduce(lambda x,y:x+y, lst)

print toHex(encrypt("Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal", "ICE"))
'''

#---------------------------------------------------------------------------------
#Problem 6, base64 to hex then decrypting from unknown byte size XOR
from itertools import cycle, izip, islice, tee

def count_binary_ones(X):
  result = 0
  while X != 0:
    result = result + 1
    X &= X-1  
  return result

def HammingDist(str1, str2):
	#print "".join(format(ord(x), "b") for x in str1) 
	X = int(binascii.hexlify(str1),16) ^ int(binascii.hexlify(str2),16)
	return count_binary_ones(X)

def NormHamming(str0, length):
	total = int(math.floor(len(str0)/length - 1))
	summ = sum(HammingDist(str0[(i)*length:(i+1)*length], str0[(i+1)*length:(i+2)*length]) for i in range(total))
	ave = summ*1.0/total
	return ave/length

def splitIntoKey(data, keySize):
	return [data[i:i+keySize] for i in range(0, len(data), keySize)]
def splitIntoKey2(data, keySize):
	return [data[i::keySize] for i in range(keySize)]

def is_ascii(s):
	return all(c in string.printable for c in s)

def repeating_xor_decrypt(text, key):
    return ''.join([chr(ord(a) ^ ord(k)) for a, k in zip(text, cycle(key))])
#print splitIntoKey("I dont like things that don't work", 3)
#print splitIntoKey2("I dont like things that don't work", 3)

#print HammingDist("this is a test", "wokka wokka!!!")

data = ""
filename = '6.txt'
for line in open(filename):
  data += line.strip()
data = base64.b64decode(data)



bestHam = float('inf')
for keySize in range(2,40):
  curHam = NormHamming(data,keySize)
  if curHam < bestHam:
    bestHam = curHam
    bestKey = keySize

keyBlocks = splitIntoKey(data, bestKey)
'''
for d in splitIntoKey(data, bestKey)[:100]:
	print (d + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	for j in xrnge(0, 255):
		if is_ascii(encrypt(d, chr(j))):
			print(encrypt(d, chr(j))+", "+chr(j))
		j=j+1

'''

key = (recover_xor_key(blocks) for blocks in keyBlocks)
plaintext = repeating_xor_decrypt(data, "Vigenere") 
score = score_text(plaintext)
print score




#print encrypt(data, "Vigenere")
'''
for i in xrange(0, 255):
	if is_ascii4(decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".decode('hex'), chr(i))):
		print decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".decode('hex'), chr(i))
'''

#flag = "0005120f1d111c1a3900003712011637080c0437070c0015".decode('hex')
#key = "fu"
#print(encrypt("0e140e140e140e1d071d0e140e14071d071d071d071d071d071d4612030146021410021e".decode('hex'), key))
#----------------------------------------------------------------------------
#97-14=83, 97-20=77
#0,6,0,6,0,6,0,15,-7,15,0,6,0,6
#	0,0,0,0,-7,0,0
#	6,6,6,15,15,6,6
'''
01110100011010000110100101110011001000000110100101110011001000000110000100100000011101000110010101110011011101000111011101101111011010110110101101100001001000000111011101101111011010110110101101100001001000010010000100100001
0111010001101000011010010111001100100000011010010111001100100000011000010010000001110100011001010111001101110100
0111011101101111011010110110101101100001001000000111011101101111011010110110101101100001001000010010000100100001
11101001101000110100111100111000001101001111001110000011000011000001110100110010111100111110100
1110100 1101000 1101001 1110011 100000 1101001 1110011 100000 1100001 100000 1110100 1100101 1110011 1110100
7		7		7		7		6		7		7		6		7		6		7		7		7		7
7		7		7		7		7		6		7		7		7		7		7		6		6		6
1110111 1101111 1101011 1101011 1100001 100000 1110111 1101111 1101011 1101011 1100001 100001 100001 100001
'''