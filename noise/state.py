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

class SymmetricState(object):
    '''
    Implemented as per Noise Protocol specification - paragraph 5.2.
    The initialize_symmetric function takes different required argument, 
    which contains protocol_name.
    '''
    def __init__(self, cipher, hasher, protocol_name=None):
        self.hasher = hasher
        self.cipher_state = CipherState(cipher)

        if protocol_name is not None:
            self.initialize_symmetric(self, protocol_name)

    def initialize_symmetric(self, protocol_name):
        diff = self.hasher.HASHLEN - len(protocol_name)

        # If protocol_name is less than or equal to HASHLEN bytes in length, 
        # sets h equal to protocol_name with zero
        # bytes appended to make HASHLEN bytes. Otherwise sets h = HASH(protocol_name).
        if diff >= 0:
            self.h = protocol_name + bytes(diff)
        else:
            self.h = self.hasher.hash(protocol_name)

        self.ck = self.h
        self.cipher_state.initialize_key(empty)

    def get_handshake_hash(self):
        return self.h

    def mix_key(self, input_key_material):
        # Sets ck, temp_k = HKDF(ck, input_key_material, 2).
        self.ck, temp_k = self.hasher.hkdf(self.ck, input_key_material, 2)

        # If HASHLEN is 64, then truncates temp_k to 32 bytes.
        if self.hasher.HASHLEN == 64:
            temp_k = temp_k[:32]

        # Calls InitializeKey(temp_k).
        self.cipher_state.initialize_key(temp_k)

    def mix_hash(self, data):
        # Sets h = HASH(h + data).
        self.h = self.hasher.hash(self.h + data)

    def mix_key_and_hash(self, input_key_material: bytes):
        # Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
        self.ck, temp_h, temp_k = self.hasher.hkdf(self.ck, input_key_material, 3)
        # Calls MixHash(temp_h).
        self.mix_hash(temp_h)
        # If HASHLEN is 64, then truncates temp_k to 32 bytes.
        if self.hasher.HASHLEN == 64:
            temp_k = temp_k[:32]
        # Calls InitializeKey(temp_k).
        self.cipher_state.initialize_key(temp_k)

    def encrypt_and_hash(self, plaintext):
        '''
        Sets ciphertext = EncryptWithAd(h, plaintext), 
        calls MixHash(ciphertext), and returns ciphertext. Note that if
        k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext
        '''
        ciphertext = self.cipher_state.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext):
        '''
        Sets plaintext = DecryptWithAd(h, ciphertext), 
        calls MixHash(ciphertext), and returns plaintext. Note that if
        k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
        '''
        plaintext = self.cipher_state.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self):
        '''
        Returns a pair of CipherState objects for encrypting/decrypting transport messages
        '''
        temp_k1, temp_k2 = self.hasher.hkdf(self.ck, b'')

        if self.hasher.HASHLEN == 64:
            temp_k1, temp_k2 = temp_k1[:32], temp_k2[:32]

        c1 = CipherState(self.cipher_state.cipher, temp_k1)
        c2 = CipherState(self.cipher_state.cipher, temp_k2)
        return c1, c2
