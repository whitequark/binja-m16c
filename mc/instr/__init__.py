from abc import ABCMeta, abstractmethod

from ..helpers import *


__all__  = ['Instruction', 'InstrShortOpcode', 'InstrLongOpcode']


class Instruction(metaclass=ABCMeta):
    opcodes = {}

    def __new__(cls, decoder=None):
        if decoder is None:
            return object.__new__(cls)
        else:
            entry  = cls.opcodes
            offset = 0
            while isinstance(entry, dict):
                byte   = decoder.peek(offset // 8)
                nibble = (byte >> (4 - (offset % 8))) & 0xf
                entry  = entry[nibble]
                offset += 4
            return object.__new__(entry)

    def name(self):
        return 'unimplemented'

    @abstractmethod
    def length(self):
        pass

    @abstractmethod
    def decode(self, decoder, addr):
        pass

    @abstractmethod
    def encode(self, encoder, addr):
        pass

    def analyze(self, info, addr):
        info.length += self.length()

    def render(self, addr):
        return asm(
            ('instr', self.name()),
            ('opsep', ' ' * (8 - len(self.name())))
        )

    def lift(self, il, addr):
        il.append(il.unimplemented())


class InstrShortOpcode:
    def length(self):
        return 1

    def decode(self, decoder, addr):
        self.opcode = decoder.unsigned_byte()

    def encode(self, encoder, addr):
        encoder = encoder.unsigned_byte(self.opcode)


class InstrLongOpcode:
    def length(self):
        return 2

    def decode(self, decoder, addr):
        self.opcode = decoder.unsigned_word()

    def encode(self, encoder, addr):
        encoder = encoder.unsigned_word(self.opcode)
