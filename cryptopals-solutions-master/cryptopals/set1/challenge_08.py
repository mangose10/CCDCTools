def detect_ecb(ciphertext):
    """Detect if the given ciphertext was encoded with mode ECB."""

    # ECB block size
    block_size = 16

    # Chunk ciphertext into ECB-sized blocks
    blocks = zip(*([iter(ciphertext)] * block_size))

    # ECB will likely have repeating blocks
    return len(blocks) != len(set(blocks))


def test(ciphertexts, ecb_ciphertext):
    for ciphertext in ciphertexts:
        if detect_ecb(ciphertext):
            break

    assert ciphertext == ecb_ciphertext
