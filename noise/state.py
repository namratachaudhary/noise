from patterns import HandshakePatterns

class CipherState(object):
    def __init__(self, cipher, key=empty):
        self.cipher = cipher
        self.initialize_key(key)

    @property
    def has_key(self):
        return self.k is not empty

    def encrypt(self, ad, plaintext):
        '''
        Encrypt encrypts the plaintext and then appends the ciphertext and an
        authentication tag across the ciphertext and optional authenticated data to
        out. This method automatically increments the nonce after every call, so
        messages must be decrypted in the same order.
        '''
        if self.k is empty:
            return plaintext
        ret = self.cipher.encrypt(self.k, self.n, ad, plaintext)
        self.n += 1
        return ret

    def decrypt(self, ad, ciphertext):
        '''
        Decrypt checks the authenticity of the ciphertext and authenticated data and
        then decrypts and appends the plaintext to out. This method automatically
        increments the nonce after every call, messages must be provided in the same
        order that they were encrypted with no missing messages.
        '''
        if self.k is empty:
            return ciphertext
        ret = self.cipher.decrypt(self.k, self.n, ad, ciphertext)
        self.n += 1
        return ret
