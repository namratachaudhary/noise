import sys
import hmac
import hashlib

if sys.version_info[0] == 3:
    buffer = lambda x: x

class Hkdf(object) :
    '''
    Ref to RFC : http://tools.ietf.org/html/rfc5869
    '''

    def __init__(self, salt, input_key_material, hash=hashlib.sha256):
        '''
        See the HKDF RFC to check how these values are to be set.

        @param hash : The hash to be used, defaults to sha256
        @param salt : salt should be a random, application-specific byte string
        @param input_key_material : data needed to generate prk

        @type prk  : The pseudorandom key , composed from salt and ikm.
        '''
        self._hash = hash
        self._prk  = self._extract(salt, input_key_material)

    def expand(self, info=b"", output_length=32):
        '''
        Generate output key material 

        @param info : data needed to generate the okm
        @param output_length : length in bytes of the key to generate
        '''
        return self._expand(info, output_length)

    def _extract(self, salt, input_key_material):
        '''
        Extract prk from salt and ikm.

        @param  salt 
        @param  input_key_material 
        @return prk 
        '''
        hash_len = 32 # tofix
        if salt == None or len(salt) == 0 :
            salt = bytearray((0,) * hash_len)

        return hmac.new(bytes(salt), buffer(input_key_material), self._hash).digest()

    def _expand(self, info=b"", output_length=32):
        '''
        Expand info alongwith prk
        
        @param info
        @param output_length
        @return okm
        '''
        hash_len = 32 # tofix
        output_length = int(output_length)

        if output_length > 255 * hash_len :
            raise Exception("Cannot expand to more than 255 * %d = %d bytes using the specified hash function" %\
                (hash_len, 255 * hash_len))

        iterations = output_length // hash_len + (0 if output_length % hash_len == 0 else 1)
        output_key_material = b""
        output_block = b""

        for counter in range(iterations) :
            output_block = hmac.new(self._prk, buffer(output_block + info + bytearray((counter + 1,))),\
                self._hash).digest()
            output_key_material += output_block

        return output_key_material[:output_length]
