from urlparse import parse_qsl
from re import sub
from cryptopals.util.pkcs_7 import pkcs7_pad
from cryptopals.set2.challenge_11 import encrypt_aes_ecb
from cryptopals.set2.challenge_12 import detect_block_size
from cryptopals.set2.challenge_12 import detect_ecb
from cryptopals.set1.challenge_07 import decrypt_aes_ecb

_uid = 10
_registered_emails = set()
_encryption_key = 'YELLOW SUBMARINE'

def kv_encode(pairs):
    """Encodes a list of tuples as k=v, ignoring & and = chars in value."""
    return '&'.join([
        key + '=' + sub(r'&|=', '', value) for key, value in pairs
    ])

def profile_for(email):
    """Registers a profile for the given email."""
    global _uid

    if email in _registered_emails:
        raise Exception('Email already registered.')

    # Build the profile for this email
    profile = [
        ('email', email),
        ('uid', str(_uid)),
        ('role', 'user')
    ]

    # Increment the uid for the next profile and 'register' the email
    _uid += 1
    _registered_emails.add(email)

    encoded = kv_encode(profile)

    # Encrypt the encoded profile
    return encrypt_aes_ecb(encoded, _encryption_key)

def decrypt_profile(ciphertext):
    """Decrypts and returns a generated profile."""
    plaintext = decrypt_aes_ecb(ciphertext, _encryption_key)

    profile = dict(parse_qsl(plaintext))

    if profile['email'] not in _registered_emails:
        raise Exception('Email not registered.')

    return profile

def assume_admin_role(profile_function):
    """Given a profile function, generate a valid profile with role=admin."""
    block_size = detect_block_size(profile_function)

    # Create padded text that is likely to repeat when using ECB mode
    repeating_plaintext = 'ff' * block_size * 2

    if detect_ecb(profile_function(repeating_plaintext), block_size) == False:
        raise Exception('profile_function does not appear to use ECB.')

    # First, we want to construct a valid block containing 'admin'
    admin_block = pkcs7_pad('admin', block_size)

    # Craft an email long enough to have the admin block at a 0 offset
    email_length = block_size - len('email=')
    email = 'a' * (email_length - len('@bar.com')) + '@bar.com'

    admin_block_profile = profile_function(email + admin_block)
    encrypted_admin_block = admin_block_profile[block_size:block_size * 2]

    # Now we want to construct a situation where 'role=' is the end of a block
    email_length = email_length + (block_size - len('&uid=XX&role='))
    email = 'b' * (email_length - len('@bar.com')) + '@bar.com'

    normal_profile = profile_function(email)

    # Switch the last block with the admin block
    admin_profile = normal_profile[:-block_size] + encrypted_admin_block

    return admin_profile


def test():
    admin_profile_cookie = assume_admin_role(profile_for)
    admin_profile = decrypt_profile(admin_profile_cookie)

    assert 'role' in admin_profile
    assert 'admin' == admin_profile['role']
