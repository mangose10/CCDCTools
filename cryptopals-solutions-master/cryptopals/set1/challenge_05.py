from itertools import cycle


def repeating_xor_encrypt(text, key):
    return ''.join([chr(ord(a) ^ ord(k)) for a, k in zip(text, cycle(key))])


def test(plaintext, key, expected_ciphertext):
    ciphertext = repeating_xor_encrypt(plaintext, key).encode("hex")

    assert ciphertext == expected_ciphertext
