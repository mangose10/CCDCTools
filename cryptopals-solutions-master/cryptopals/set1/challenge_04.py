from cryptopals.set1.common import recover_xor_key


def test(hex_strings, expected):
    english_score = {
        score: text for key, score, text in [
            recover_xor_key(hex_string.decode('hex'))
            for hex_string in hex_strings
        ]
    }

    best_score = min(english_score)

    return english_score[best_score]
