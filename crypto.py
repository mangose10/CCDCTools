import binascii
import string
import base64


def hexToBase64(s):
	decoded = binascii.unhexlify(s)
	return base64.b64encode(decoded).decode('ascii')

x = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
expectedY = ''
y = hexToBase64(x)
#print(y)
#print(expectedY)


#------------------------------------------------------------------------------

def encrypt(plaintext, key):

	ciphertext = []
	for i in xrange(0, len(plaintext)):
		ciphertext.append(ord(plaintext[i]) ^ ord(key[i % len(key)]))

	return ''.join(map(chr, ciphertext))

decrypt = encrypt
#print decrypt("2e0c010d46000048074900090b191f0d484923091f491004091a1648071d070d081d1a070848".decode('hex'), "Here is a sample. Pay close attention!".decode('hex'))
#print decrypt("2e0c010d46000048074900090b191f0d484923091f491004091a1648071d070d081d1a070848".decode('hex'), "fish".decode('hex'))

#-----------------------------------------------------------------------------

def is_ascii(s):
	return all(ord(c) < 175 for c in s)
def is_ascii2(s):
	return all(ord(c) > 30 | ord(c) <= 32 for c in s)
def is_ascii3(s):
	return (is_ascii(s) & is_ascii2(s))
def is_ascii4(s):
	return all(c in string.printable for c in s)

i = 0
j = 0
f = open("f.txt")

while(i<256):
	j=0
	key = f.readline()
	key = key[0:-1]
	while (j < 256):
		if is_ascii4(encrypt(key.decode('hex'), chr(j))):
			print(encrypt(key.decode('hex'), chr(j))+", "+chr(j)+", "+str(i))
		j=j+1
	i=i+1

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