from cryptopals.set1.common import recover_xor_key


def test(ciphertext, expected_plaintext):
    ciphertext = ciphertext.decode('hex')

    key, score, plaintext = recover_xor_key(ciphertext)

    assert plaintext == expected_plaintext
