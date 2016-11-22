def fixed_xor(str1, str2):
    return ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(str1, str2)])


def test(string_a, string_b, expected):
    string_a = string_a.decode('hex')
    string_b = string_b.decode('hex')

    assert fixed_xor(string_a, string_b).encode('hex') == expected
