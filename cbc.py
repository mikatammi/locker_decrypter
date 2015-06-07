class zeropad:

    def __init__(self, block_size):
        assert block_size > 0 and block_size < 256
        self.block_size = block_size

    def pad(self, pt):
        ptlen = len(pt)
        padsize = self.block_size - ((ptlen + self.block_size - 1) % self.block_size + 1)
        return pt + "\0" * padsize

    def unpad(self, ppt):
        assert len(ppt) % self.block_size == 0
        offset = len(ppt)
        if (offset == 0):
            return ''
        end = offset - self.block_size + 1
        while (offset > end):
            offset -= 1;
            if (ppt[offset] != "\0"):
                return ppt[:offset + 1]
        assert false

class cbc:

    def __init__(self, padding, cipher, iv):
        assert padding.block_size == cipher.block_size;
        assert len(iv) == cipher.block_size;
        self.padding = padding
        self.cipher = cipher
        self.iv = iv

    def encrypt(self, pt):
        ppt = self.padding.pad(pt)
        offset = 0
        ct = ''
        v = self.iv
        while (offset < len(ppt)):
            block = ppt[offset:offset + self.cipher.block_size]
            block = self.xorblock(block, v)
            block = self.cipher.encrypt(block)
            ct += block
            offset += self.cipher.block_size
            v = block
        return ct;

    def decrypt(self, ct):
        assert len(ct) % self.cipher.block_size == 0
        ppt = ''
        offset = 0
        v = self.iv
        while (offset < len(ct)):
            block = ct[offset:offset + self.cipher.block_size]
            decrypted = self.cipher.decrypt(block)
            ppt += self.xorblock(decrypted, v)
            offset += self.cipher.block_size
            v = block
        pt = self.padding.unpad(ppt)
        return pt;

    def xorblock(self, b1, b2):
        # sorry, not very Pythonesk
        i = 0
        r = '';
        while (i < self.cipher.block_size):
             r += chr(ord(b1[i]) ^ ord(b2[i]))
             i += 1
        return r
