import random
from cryptopals.util.pkcs_7 import pkcs7_strip, PKCS7PaddingError
from cryptopals.set2.challenge_10 import encrypt_aes_cbc, decrypt_aes_cbc
from cryptopals.set2.challenge_11 import pseudorandom_aes_key

key = pseudorandom_aes_key()


def encrypt_token(plaintext):
    """Encrypts the plaintext with a consistent key."""
    iv = pseudorandom_aes_key()
    ciphertext = encrypt_aes_cbc(plaintext, key, iv)

    return (ciphertext, iv)


def consume_token(ciphertext, iv):
    """Simulates a server consuming an encrypted token. Returns false if there
    is a padding error, true if not.
    """
    try:
        decrypt_aes_cbc(ciphertext, key, iv)
        return True
    except PKCS7PaddingError:
        return False


def chunk(text):
    """Group text into a set of 16 byte blocks."""
    i = 0

    while i < len(text):
        yield text[i:i + 16]
        i += 16


def padding_oracle_attack(ciphertext, iv):
    solution = ''
    previous_block = iv

    for block in chunk(ciphertext):
        # Used to corrupt block to produce valid padding
        poison_block = bytearray(16)

        # The block after decryption but before XORing
        intermediate_block = bytearray(16)

        # The plaintext result of attacking the block
        plaintext_block = bytearray(16)

        # Attack the block one byte at a time starting at the end (-1 index)
        for i in [x for x in xrange(-1, -17, -1)]:
            # The number of bytes padding necessary to produce valid padding
            padding = abs(i)

            # Using the solved bytes in the intermediate block, set up the
            # poison block to produce valid padding for all but the i-th byte
            for j in xrange(i + 1, 16):
                poison_block[j] = intermediate_block[j] ^ padding

            # Try all 256 possibilities for the byte at i
            for j in xrange(0, 256):
                poison_block[i] = j
                valid = consume_token(str(poison_block) + block, iv)

                if valid:
                    break
            else:
                raise Exception('No valid byte found at index %d' % i)

            # Store the now known value for the intermediate_block byte
            intermediate_block[i] = j ^ padding

            # Calculate the original plaintext from the intermediate block
            plaintext_block[i] = intermediate_block[i] ^ ord(previous_block[i])

        solution += ''.join(map(chr, plaintext_block))
        previous_block = block

    return pkcs7_strip(solution)


def test(strings):
    plaintext = random.choice(strings)
    ciphertext, iv = encrypt_token(plaintext)

    assert padding_oracle_attack(ciphertext, iv) == plaintext
