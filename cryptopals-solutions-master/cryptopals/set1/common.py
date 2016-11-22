from __future__ import division
import collections
import math
import string

english_letter_frequency = collections.defaultdict(int, {
    ' ': .1217,
    'a': .0609,
    'b': .0105,
    'c': .0284,
    'd': .0292,
    'e': .1136,
    'f': .0179,
    'g': .0138,
    'h': .0341,
    'i': .0544,
    'j': .0024,
    'k': .0041,
    'l': .0292,
    'm': .0276,
    'n': .0544,
    'o': .0600,
    'p': .0195,
    'q': .0024,
    'r': .0495,
    's': .0568,
    't': .0803,
    'u': .0243,
    'v': .0097,
    'w': .0138,
    'x': .0024,
    'y': .0130,
    'z': .0003,
    '_': .0657,
})

def recover_xor_key(cipher_text):
    xor_text_map = {
        char: single_byte_xor(cipher_text, char) for char in string.printable
    }

    scores = {
        char: score_text(text) for char, text in xor_text_map.items()
    }

    key = min(scores, key = scores.get)

    return (key, scores[key], xor_text_map[key])

def single_byte_xor(string, character):
    return ''.join([chr(ord(a) ^ ord(character)) for a in string])

def score_text(text):
    counter = collections.Counter([
        char.lower() if char not in string.punctuation else '_'
        for char in text
    ])

    total = len(text)

    return sum([
        math.pow(abs(english_letter_frequency[char] - (count / total)), 2)
        if char in string.printable else 1
        for char, count in counter.items()
    ])
