import struct


__all__ = ['Decoder', 'Encoder']


class BufferTooShort(Exception):
    pass


class Decoder:
    def __init__(self, buf):
        self.buf, self.pos = buf, 0

    def peek(self, offset):
        if len(self.buf) - self.pos <= offset:
            raise BufferTooShort

        return self.buf[self.pos + offset]

    def _unpack(self, fmt):
        size = struct.calcsize(fmt)
        if len(self.buf) - self.pos < size:
            raise BufferTooShort

        items = struct.unpack_from('<' + fmt, self.buf, self.pos)
        self.pos += size
        if len(items) == 1:
            return items[0]
        else:
            return items

    def unsigned_byte(self):
        return self._unpack('B')

    def unsigned_word(self):
        return self._unpack('H')

    def unsigned_triple(self):
        return self.unsigned_word() | (self.unsigned_byte() << 16)

    def unsigned(self, width):
        if width == 1:
            return self.unsigned_byte()
        elif width == 2:
            return self.unsigned_word()
        elif width == 3:
            return self.unsigned_triple()
        else:
            raise ValueError("invalid unsigned width {}".format(width))

    def signed_byte(self):
        return self._unpack('b')

    def signed_word(self):
        return self._unpack('h')

    def signed(self, width):
        if width == 1:
            return self.signed_byte()
        elif width == 2:
            return self.signed_word()
        else:
            raise ValueError("invalid signed width {}".format(width))


class Encoder:
    def __init__(self):
        self.buf = bytearray()

    def _pack(self, fmt, *items):
        offset = len(self.buf)
        self.buf += b'\x00' * struct.calcsize(fmt)
        struct.pack_into('<' + fmt, self.buf, offset, *items)

    def unsigned_byte(self, value):
        self._pack('B', value)

    def unsigned_word(self, value):
        self._pack('H', value)

    def unsigned_triple(self, value):
        self.unsigned_word(value & 0xFFFF)
        self.unsigned_byte(value >> 16)

    def unsigned(self, value, width):
        if width == 1:
            self.unsigned_byte(value)
        elif width == 2:
            self.unsigned_word(value)
        elif width == 3:
            self.unsigned_triple(value)
        else:
            raise ValueError("invalid unsigned width {}".format(width))

    def signed_byte(self, value):
        self._pack('b', value)

    def signed_word(self, value):
        self._pack('h', value)

    def signed(self, value, width):
        if width == 1:
            self.signed_byte(value)
        elif width == 2:
            self.signed_word(value)
        else:
            raise ValueError("invalid signed width {}".format(width))
