def pkcs7_strip(plaintext):
    """Strip PKCS#7 padding from plaintext, or raise exception if invalid."""
    padding_size = ord(plaintext[-1])

    if padding_size == 0 or padding_size > len(plaintext):
        raise PKCS7PaddingError("Invalid padding size: %d" % padding_size)

    padding = plaintext[-padding_size:]
    expected = chr(padding_size) * padding_size

    if padding != expected:
        raise PKCS7PaddingError("Invalid PKCS#7 padding: %s" % padding)

    return plaintext[:-padding_size]


def pkcs7_pad(plaintext, blocksize):
    """Pad the given plaintext to a multiple of the blocksize per PKCS #7."""
    padding = blocksize - (len(plaintext) % blocksize)

    return plaintext + (chr(padding) * padding)


class PKCS7PaddingError(ValueError):
    """Raised when the plaintext has an invalid padding."""
