from patterns import HandshakePatterns
from cipher_suite import SuiteInterface
from exceptions import NoiseMaxNonceError

class Empty(Singleton):
    """
    Special empty value
    Use ``empty'' instantiation
    """
    pass

empty = Empty()

MAX_NONCE = 2 ** 64 - 1

class CipherState(object):
    '''
    Implemented as per Noise Protocol specification - paragraph 5.1.
    The initialize_key() function takes additional required argument - noise_protocol.
    This class holds an instance of Cipher wrapper. 
    It manages initialisation of underlying cipher function
    with appropriate key in initialize_key() and rekey() methods.
    '''

    def __init__(self, cipher, key=empty):
        self.cipher = cipher
        self.initialize_key(key)

    def initialize_key(self, key):
        self.key = key
        self.none = 0

    @property
    def has_key(self):
        return self.key is not empty

    def encrypt_with_ad(self, ad, plaintext):
        '''
        Encrypt encrypts the plaintext and then appends the ciphertext and an
        authentication tag across the ciphertext and optional authenticated data to
        out. This method automatically increments the nonce after every call, so
        messages must be decrypted in the same order.
        '''
        if self.none == MAX_NONCE:
            raise NoiseMaxNonceError('Nonce has depleted!')

        if self.key is empty:
            return plaintext

        ciphertext = self.cipher.encrypt(self.key, self.none, ad, plaintext)
        self.none += 1
        return ciphertext

    def decrypt_with_ad(self, ad, ciphertext):
        '''
        Decrypt checks the authenticity of the ciphertext and authenticated data and
        then decrypts and appends the plaintext to out. This method automatically
        increments the nonce after every call, messages must be provided in the same
        order that they were encrypted with no missing messages.
        '''
        if self.none == MAX_NONCE:
            raise NoiseMaxNonceError('Nonce has depleted!')

        if self.key is empty:
            return ciphertext

        plaintext = self.cipher.decrypt(self.key, self.nonce, ad, ciphertext)
        self.nonce += 1
        return plaintext

    def rekey(self):
        self.key = self.cipher.rekey(self.key)
        self.cipher.initialize(self.key)
