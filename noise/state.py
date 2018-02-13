from patterns import HandshakePatterns
from cipher_suite import SuiteInterface
from exceptions import NoiseMaxNonceError, HandshakeError

class Empty(SuiteInterface):
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


class HandshakeState(object):

    def __init__(self, dh, cipher, hasher):
        self.dh = dh
        self.cipher = cipher
        self.hasher = hasher

    def initialize(self, handshake_pattern, initiator, prologue=b'',
                   s=empty, e=empty, rs=empty, re=empty):

        # Originally in specification:
        # "Derives a protocol_name byte sequence by combining the names for
        # the handshake pattern and crypto functions, as specified in Section 8."
        # Instead, we supply the NoiseProtocol to the function. 
        # The protocol name should already be validated.

        protocol_name = b'_'.join((handshake_pattern, self.dh.NAME,
                                   self.cipher.NAME, self.hasher.NAME))
        self.symmetricstate = SymmetricState(self.dh, self.cipher, self.hasher,
                                             protocol_name)
        self.symmetricstate.mixhash(prologue)
        self.s = s if s is not None else Empty()
        self.e = e if e is not None else Empty()
        self.rs = rs if rs is not None else Empty()
        self.re = re if re is not None else Empty()

        # Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern, with the specified
        # public key as input (...). If both initiator and responder have pre-messages, the initiator’s public keys are
        # hashed first

        pattern = HandshakePatterns(handshake_pattern)
        if pattern.i_pre not in ('', 's', 'e', 'se'):
            raise HandshakeError("Invalid initiator pre-message")
        if pattern.r_pre not in ('', 's', 'e', 'se'):
            raise HandshakeError("Invalid responder pre-message")
        for token in pattern.i_pre:
            if token == 's':
                if self.s is empty:
                    raise HandshakeError("No static public key (initiator)")
                self.symmetricstate.mixhash(self.s.public)
            elif token == 'e':
                if self.e is empty:
                    raise HandshakeError("No ephemeral public key (initiator)")
                self.symmetricstate.mixhash(self.e.public)

        # Sets message_patterns to the message patterns from handshake_pattern

        for token in pattern.r_pre:
            if token == 's':
                if self.rs is empty:
                    raise HandshakeError("No static public key (responder)")
                self.symmetricstate.mixhash(self.rs)
            elif token == 'e':
                if self.re is empty:
                    raise HandshakeError("No ephemeral public key (responder)")
                self.symmetricstate.mixhash(self.re)

        self.message_patterns = list(pattern.message_patterns)

    def write_message(self, payload, message_buffer):
        # Fetches and deletes the next message pattern from message_patterns, 
        # then sequentially processes each token
        # from the message pattern
        # currently using '.append' protocol, but may need changing
        message_pattern = self.message_patterns.pop(0)

        for token in message_pattern:

            if token == 'e':
                self.e = self.dh.generate_keypair()
                message_buffer.append(self.e.public_key)
                self.symmetricstate.mixhash(self.e.public_key)

            elif token == 's':
                msg = self.symmetricstate.encrypt_and_hash(self.s.public_key)
                message_buffer.append(msg)
    
            elif token[:2] == 'dh':
                try:
                    x = {'e': self.e, 's': self.s}[token[2]]
                    y = {'e': self.re, 's': self.rs}[token[3]]
                except KeyError:
                    raise HandshakeError("Invalid pattern: " + token)
                self.symmetricstate.mixkey(self.dh.DH(x, y))

            else:
                raise HandshakeError("Invalid pattern: " + token)

        message_buffer.append(self.symmetricstate.encrypt_and_hash(payload))

        if len(self.message_patterns) == 0:
            return self.symmetricstate.split()

    def read_message(self, message, payload_buffer):
        # Fetches and deletes the next message pattern from message_patterns, 
        # then sequentially processes each token
        # from the message pattern
        # currently using '.append' protocol, but may need changing
        message_pattern = self.message_patterns.pop(0)

        for token in message_pattern:
    
            if token == 'e':
                if len(message) < self.dh.DHLEN:
                    raise HandshakeError("Message too short""")
                self.re = message[:self.dh.DHLEN]
                message = message[self.dh.DHLEN:]
                self.symmetricstate.mixhash(self.re)
    
            elif token == 's':
                has_key = self.symmetricstate.cipherstate.has_key
                nbytes = self.dh.DHLEN + 16 if has_key else self.dh.DHLEN
    
                if len(message) < nbytes:
                    raise HandshakeError("Message too short""")
                temp, message = message[:nbytes], message[nbytes:]
    
                if has_key:
                    self.rs = self.symmetricstate.decrypt_and_hash(temp)
                else:
                    self.rs = temp
    
            elif token[:2] == 'dh':
                try:
                    x = {'e': self.e, 's': self.s}[token[2]]
                    y = {'e': self.re, 's': self.rs}[token[3]]
  
                except KeyError:
                    raise HandshakeError("Invalid pattern: " + token)
  
                self.symmetricstate.mixkey(self.dh.DH(x, y))
            else:
                raise HandshakeError("Invalid pattern: " + token)
  
        payload_buffer.append(self.symmetricstate.decrypt_and_hash(message))

        if len(self.message_patterns) == 0:
            return self.symmetricstate.split()
