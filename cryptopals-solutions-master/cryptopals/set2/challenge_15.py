from cryptopals.util.pkcs_7 import pkcs7_strip, PKCS7PaddingError


def test(padded, expected):
    try:
        plaintext = pkcs7_strip(padded)

        assert plaintext == expected
    except PKCS7PaddingError:
        assert expected is None, 'Exception thrown on valid plaintext.'
