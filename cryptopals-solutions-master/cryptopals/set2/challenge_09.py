from cryptopals.util.pkcs_7 import pkcs7_pad


def test(plaintext, blocksize, expected):
    assert pkcs7_pad(plaintext, blocksize) == expected
