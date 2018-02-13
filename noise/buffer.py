class NoiseBuffer(object):
    '''
    Bytestring buffer with append interface.
    The buffer is pre-allocated. 

    strict mode prevents arbitrary appends beyond the original 
    buffer size.

    Pre-allocated bytestring buffer with append interface
    '''
    def __init__(self, nbytes=0, strict=False):
        self.buffer = bytearray(nbytes)
        self.length = 0
        self.strict = strict

    def __len__(self):
        return self.length

    def append(self, val):
        '''
        Append byte string val to buffer

        If the result exceeds the length of the buffer, then
        if in strict mode, a ValueError is raised.
        otherwise, the buffer is extended as necessary.
        '''
        new_len = self.length + len(val)
        to_add = new_len - len(self.buffer)

        if self.strict and to_add > 0:
            raise ValueError("Cannot resize buffer")

        self.buffer[self.length:new_len] = val
        self.length = new_len

    def __bytes__(self):
        '''
        Return immutable copy of buffer

        if in strict mode, 
        return entire pre-allocated buffer, initialized to 0x00
        otherwise, return only written bytes.
        '''
        if self.strict:
            return bytes(self.buffer)
        else:
            return bytes(self.buffer[:self.length])