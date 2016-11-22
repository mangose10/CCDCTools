from __future__ import division
from common import recover_xor_key, score_text
from itertools import cycle, izip, islice, tee

# Taken from https://docs.python.org/2/library/itertools.html#recipes
def _pairwise(iterable):
    """s -> (s0,s1), (s1,s2), (s2, s3), ..."""
    a, b = tee(iterable)
    next(b, None)
    return izip(a, b)

def hamming_distance(str1, str2):
    """Calculate the hamming distance of two strings."""
    return sum([
        bin(ord(chr1) ^ ord(chr2)).count("1")
        for chr1, chr2 in zip(str1, str2)
    ])

def block_iterator(text, block_size):
    """Group text into a set of block_size blocks."""
    return izip(*([iter(text)] * block_size))

def block_hamming_distance(text, start, stop):
    """Return a sorted list of hamming distances for n-length blocks."""
    blocksize_scores = []

    for blocksize in range(start, stop):
        blocks = islice(block_iterator(text, blocksize), 4)

        distance_scores = [
            hamming_distance(block1, block2) / blocksize
            for block1, block2 in _pairwise(blocks)
        ]

        avg_score = sum(distance_scores) / len(distance_scores)

        blocksize_scores.append((blocksize, avg_score))

    return sorted(blocksize_scores, key = lambda pair: pair[1])

def transpose(iterable):
    """[[abc], [def], [ghi]] => [[adf], [beh], [cfi]]"""
    return [''.join(block) for block in zip(*iterable)]

def repeating_xor_decrypt(text, key):
    return ''.join([chr(ord(a) ^ ord(k)) for a, k in zip(text, cycle(key))])

def break_repeating_key_xor(ciphertext):
    # Calculate the edit distance for keysizes ranging from 2 to 40
    keysize_scores = block_hamming_distance(ciphertext, 2, 40)

    best_key = None
    best_score = None

    # Try the 3 keysizes with the lowest edit distance
    for keysize,_ in keysize_scores[:3]:
        # Transpose the blocks
        key_blocks = transpose(block_iterator(ciphertext, keysize))

        # Guess the single char xor key for each block and assemble the key
        key = ''.join([
            recover_xor_key(block)[0] for block in key_blocks
        ])

        # Decrypt into plaintext and score the result
        plaintext = repeating_xor_decrypt(ciphertext, key)
        score = score_text(plaintext)

        if (best_score == None or best_score > score):
            best_score = score
            best_key = key

    return key


def test(ciphertext, expected_key):
    key = break_repeating_key_xor(ciphertext)

    assert key == expected_key
