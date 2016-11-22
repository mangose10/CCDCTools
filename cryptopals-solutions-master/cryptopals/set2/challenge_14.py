import random
from itertools import chain, izip
from cryptopals.set2.challenge_11 import pseudorandom_aes_key
from cryptopals.set2.challenge_11 import encrypt_aes_ecb

def aes_ecb_unknown_key_random_prefix_encrypt(secret_plaintext):
    """Return a function for encrypting input with a hidden key and string."""
    unknown_key = pseudorandom_aes_key()

    def encrypt_with_secret_plaintext(input_str):
        # Up to 4 block sizes long
        prefix_length = random.randint(0, 16 * 8)

        random_prefix = ''.join([
            chr(random.randint(0, 255))
            for i in xrange(0, prefix_length)
        ])

        return encrypt_aes_ecb(
            random_prefix + input_str + secret_plaintext,
            unknown_key
        )

    return encrypt_with_secret_plaintext

def detect_block_size(encryption_function):
    """Given a block mode encryption function, determine the block size."""
    iteration_count = 20
    string = "A"

    length = min([
        len(encryption_function(string))
        for i in range(0, iteration_count)
    ])
    previous_length = length

    # Increment the input string until the ciphertext length increases
    while (length == previous_length):
        string += "A"
        previous_length = length

        length = min([
            len(encryption_function(string))
            for i in xrange(0, iteration_count)
        ])

    # The difference in length is the block size
    return abs(length - previous_length)

def detect_ecb(encryption_function, block_size):
    """Detect if the given ciphertext was encoded with mode ECB."""

    # Create padded text that is likely to repeat when using ECB mode
    repeating_plaintext = 'a' * block_size * 4

    ciphertext = encryption_function(repeating_plaintext)

    # Chunk ciphertext into ECB-sized blocks
    blocks = zip(*([iter(ciphertext)] * block_size))

    # ECB will likely have repeating blocks
    return len(blocks) != len(set(blocks))

def block_iterator(text, block_size):
    """Group text into a set of block_size blocks."""
    return izip(*([iter(text)] * block_size))

def poison_encryption_function(encryption_function, blocksize):
    """Return an encryption function that does not have a random prefix."""
    poison_block_count = 3

    poison_block = ('\xDE\xAD' * (blocksize/2))
    guard_block  = (
        (chr(255 - char) * (blocksize - 1)) + chr(char)
        for char in xrange(0, 255)
    )

    poison = ''.join([
        poison_block + guard_block.next() for i in range(0, poison_block_count)
    ])

    def encrypt_without_prefix(input_str):
        # Loop until the poison blocks are found
        while True:
            ciphertext = encryption_function(poison + input_str)
            iterator = block_iterator(ciphertext, blocksize)
            double_iterator = zip(*[iterator]*2)

            last_block = (None, None)
            block_count = 0
            for index, block in enumerate(double_iterator):
                if block[0] != last_block[0]:
                    last_block = block
                    block_count = 1
                else:
                    block_count += 1

                if block_count == poison_block_count:
                    return ciphertext[blocksize * (index + 1) * 2:]

    return encrypt_without_prefix

def extract_block(text, index, block_size):
    """Extracts the nth block_size block of text."""
    return text[index * block_size : (index + 1) * block_size]

def lookup_table_iterator(prefix, encryption_function):
    """
    Return an iterator of (encrypted_block, char) for chars appended to prefix.
    """

    block_size = len(prefix) + 1

    return (
        (encryption_function(prefix + chr(char))[:block_size], chr(char))
        for char in chain(
            xrange(32, 127), xrange(0, 32), xrange(127, 255)
        )
    )

def decrypt_ecb_suffix(encryption_function):
    """Return unkown_string from an encryption_function with unknown key."""
    block_size = detect_block_size(encryption_function)

    if (detect_ecb(encryption_function, block_size) == False):
        raise Exception('encryption_function does not appear to use ECB.')

    # Poison the encryption function to ignore any prefix
    encrypt = poison_encryption_function(encryption_function, block_size)

    # Initialize last known block to a predefined block
    last_known_block = '\x00' * block_size

    solution = ''
    num_blocks = len(encrypt('')) / block_size

    for block_index in range(0, num_blocks):
        is_last_block = (block_index == num_blocks - 1)
        block_solution = ''

        for byte_index in range(0, block_size):
            # Build a prefix from the last known block, where:
            #   len(prefix) + len(block_solution) = blocksize - 1
            # This means the 0th block will always be len(block_solution) + 1
            # bytes "short", allowing us to solve for the 1 remaining unknown
            # byte.
            prefix = last_known_block[byte_index + 1:block_size]

            # Extract the target block from the result of encrypting the prefix
            target_block = extract_block(
                encrypt(prefix), block_index, block_size
            )

            # Generate a lookup table for the remaining unknown byte in the
            # target block.
            lookup_table = lookup_table_iterator(
                prefix + block_solution,
                encrypt
            )

            # Append the character that caused the encryption function to
            # generate the target block.
            for encrypted_block, char in lookup_table:
                if target_block == encrypted_block:
                    block_solution += char
                    break
            else:
                raise KeyError(target_block)

            # Break after reaching PKCS #7 padding.
            if is_last_block and ord(block_solution[-1]) == 1:
                block_solution = block_solution[:-1]
                break

        last_known_block = block_solution
        solution += block_solution

    return solution


def test(secret_plaintext):
    encryption_function = aes_ecb_unknown_key_random_prefix_encrypt(
        secret_plaintext)

    assert decrypt_ecb_suffix(encryption_function) == secret_plaintext
