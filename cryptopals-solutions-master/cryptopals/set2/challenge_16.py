from cryptopals.set2.challenge_10 import encrypt_aes_cbc, decrypt_aes_cbc
import re
import random

def pseudorandom_aes_key():
    """Return a 16 byte block generated pseudorandomly."""
    return ''.join([chr(random.randint(0, 255)) for i in range(0, 16)])

key = pseudorandom_aes_key()
iv = pseudorandom_aes_key()

def encode_userdata(userdata):
    """Appends userdata to a string and encodes it."""
    sanitized = re.sub(';|=', '', userdata)

    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = prefix + userdata + suffix

    return encrypt_aes_cbc(plaintext, key, iv)

def admin_check(ciphertext):
    """After decrypting, checks ciphertext for admin=true value."""
    plaintext = decrypt_aes_cbc(ciphertext, key, iv)
    attrs = map(lambda x: tuple(x.split('=')), plaintext.split(';'))

    return ("admin", "true") in attrs

def cbc_bitflip():
    """Use bitflipping to produce admin=true."""

    # First calculate the block and byte that we want to modify
    prefix_len = len("comment1=cooking%20MCs;userdata=")
    block_num = (prefix_len / 16) - 1
    offset = prefix_len % 16

    # Then set up the block where bitflipping will encode malicious chars
    poison = "_admin_true"
    first_byte = (16 * block_num) + offset
    next_byte = first_byte + len("_admin")

    ciphertext = list(encode_userdata(poison))

    # Since the block containing _admin_true will be XOR'd with the previous
    # block after decrypting, we can modify the previous block with a value
    # that when XOR'd with "_" produces 0. XORing that once again with ";"
    # means the decrypted result will have ";" in that byte position.
    ciphertext[first_byte] = chr(
        ord(ciphertext[first_byte]) ^ ord("_") ^ ord(";")
    )

    # Ditto with "="
    ciphertext[next_byte] = chr(
        ord(ciphertext[next_byte]) ^ ord("_") ^ ord("=")
    )

    return ''.join(ciphertext)


def test():
    assert admin_check(cbc_bitflip())
