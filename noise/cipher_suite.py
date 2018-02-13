from collections import namedtuple

import libnacl

from pysodium import \
    crypto_aead_chacha20poly1305_encrypt as chachapoly_encrypt, \
    crypto_aead_chacha20poly1305_decrypt as chachapoly_decrypt

# Set BLAKE2b HASHLEN
libnacl.crypto_generichash_BYTES = 64

# declare KeyPair
KeyPair = namedtuple('KeyPair', ('public_key', 'private_key'))

class SuiteInterface(object):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls ._instance is None :
            cls._instance = object.__new__(cls, *args, **kwargs)
        return cls._instance

##### Interfaces #####

class DH(SuiteInterface):

    DHLEN = None
    NAME = b""

    @classmethod
    def generate_keypair(cls):
        '''
        A DHKey is a keypair used for Diffie-Hellman key agreement.
        '''
        raise Exception("Method not implemeted")

    @classmethod
    def DH(cls, keypair, public_key):
        '''
        DH implements Diffie-Hellman key agreement
        '''
        raise Exception("Method not implemeted")

# Cipher is a AEAD cipher that has been initialized with a key.
class Cipher(SuiteInterface):
    @classmethod
    def encrypt(cls, k, n, ad, plaintext):
        '''
        Encrypt encrypts the provided plaintext with a nonce and then appends 
        ciphertext to out along with an authentication tag over the ciphertext
        and optional authenticated data
        '''
        raise Exception("Method not implemeted")

    @classmethod
    def decrypt(cls, k, n, ad, ciphertext):
        '''
        Decrypt authenticates the ciphertext and optional authenticated data and
        decrypts the provided ciphertext using the provided nonce and
        appends it to out.
        '''
        raise Exception("Method not implemeted")

class Hash(SuiteInterface):
    @classmethod 
    def hash(cls, inputbytes):
        raise Exception("Method not implemeted")

###### DH #######

class DH25519(DH):
    DHLEN = 32
    NAME = b"25519"

    @classmethod
    def generate_keypair(cls):
        return KeyPair(*libnacl.crypto_box_keypair())

    @classmethod
    def DH(cls, keypair, public_key):
        return libnacl.crypto_box_beforenm(public_key, keypair.private_key)

class DH448(DH):
    DHLEN = 56
    NAME = b"448"

###### Cipher #######

class ChaChaPoly(Cipher):
    NAME = b"ChaChaPoly"

    @classmethod
    def encrypt(cls, k, n, ad, plaintext):
        return chachapoly_encrypt(plaintext, ad, n, k)

    @classmethod
    def decrypt(cls, k, n, ad, ciphertext):
        return chachapoly_decrypt(ciphertext, ad, n, k)

class AESGCM(Cipher):
    NAME = b"AESGCM"

###### Hash #######

class SHA256(Hash):
    HASHLEN = 32
    BLOCKLEN = 64
    NAME = b"SHA256"
    hash = libnacl.crypto_hash_sha256

class SHA512(Hash):
    HASHLEN = 64
    BLOCKLEN = 128
    NAME = b"SHA512"
    hash = libnacl.crypto_hash_sha512

class BLAKE2s(Hash):
    HASHLEN = 32
    BLOCKLEN = 64
    NAME = b"BLAKE2s"

class BLAKE2b(Hash):
    HASHLEN = 64
    BLOCKLEN = 128
    NAME = b"BLAKE2b"
    hash = libnacl.crypto_generichash
