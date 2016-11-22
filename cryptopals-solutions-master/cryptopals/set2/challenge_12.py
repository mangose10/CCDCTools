from cryptopals.set2.challenge_11 import pseudorandom_aes_key
from cryptopals.set2.challenge_11 import encrypt_aes_ecb

def aes_ecb_unknown_key_encrypt(secret_plaintext):
    """Return a function for encrypting input with a hidden key and string."""
    unknown_key = pseudorandom_aes_key()

    def encrypt_with_secret_plaintext(input_str):
        return encrypt_aes_ecb(input_str + secret_plaintext, unknown_key)

    return encrypt_with_secret_plaintext

def detect_block_size(encryption_function):
    """Given a block mode encryption function, determine the block size."""
    string = "A"
    length = len(encryption_function(string))
    previous_length = length

    # Increment the input string until the ciphertext length increases
    while (length == previous_length):
        string += "A"
        previous_length = length
        length = len(encryption_function(string))

    # The difference in length is the block size
    return length - previous_length

def detect_ecb(ciphertext, block_size):
    """Detect if the given ciphertext was encoded with mode ECB."""

    # Chunk ciphertext into ECB-sized blocks
    blocks = zip(*([iter(ciphertext)] * block_size))

    # ECB will likely have repeating blocks
    return len(blocks) != len(set(blocks))

def generate_lookup_table(prefix, encryption_function):
    """Return a map of encrypted_block: char for chars appended to prefix."""
    block_size = len(prefix) + 1

    return {
        encryption_function(prefix + char)[:block_size]: char
        for char in [chr(byte) for byte in range(0, 255)]
    }

def extract_block(text, index, block_size):
    """Extracts the nth block_size block of text."""
    return text[index * block_size : (index + 1) * block_size]

def decrypt_ecb_suffix(encryption_function):
    """Return unkown_string from an encryption_function with unknown key."""
    block_size = detect_block_size(encryption_function)

    # Alias encryption function as encrypt
    encrypt = encryption_function

    # Create padded text that is likely to repeat when using ECB mode
    repeating_plaintext = 'a' * block_size * 4

    if (detect_ecb(encrypt(repeating_plaintext), block_size) == False):
        raise Exception('encryption_function does not appear to use ECB.')

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
            lookup_table = generate_lookup_table(
                prefix + block_solution,
                encryption_function
            )

            # Append the character that caused the encryption function to
            # generate the target block.
            block_solution += lookup_table[target_block]

            # Break after reaching PKCS #7 padding.
            if is_last_block and ord(block_solution[-1]) == 1:
                block_solution = block_solution[:-1]
                break

        last_known_block = block_solution
        solution += block_solution

    return solution


def test(secret_plaintext):
    encryption_oracle = aes_ecb_unknown_key_encrypt(secret_plaintext)

    return decrypt_ecb_suffix(encryption_oracle)
