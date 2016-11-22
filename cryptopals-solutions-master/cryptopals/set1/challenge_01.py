import base64


def hex_to_base64(hex_str):
    return base64.b64encode(hex_str.decode('hex'))


def test(hex_str, expected):
    assert hex_to_base64(hex_str) == expected
