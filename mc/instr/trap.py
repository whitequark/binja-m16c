from . import *


__all__ = ['Und', 'Into', 'Brk', 'Int']


class Und(SemaTrap, InstrShortOpcode):
    def name(self):
        return 'UND'

    def lift(self, il, addr):
        il.append(il.undefined())
        # or: il.append(il.trap(0x80))


class Into(SemaTrap, InstrShortOpcode):
    def name(self):
        return 'INTO'

    def lift(self, il, addr):
        il.append(il.trap(0x81))


class Brk(SemaTrap, InstrShortOpcode):
    def name(self):
        return 'BRK'

    def lift(self, il, addr):
        il.append(il.breakpoint())
        # or: il.append(il.trap(0x82))


class Int(SemaTrap, InstrShortOpcode):
    def name(self):
        return 'INT'

    def new_operands(self):
        return [OperImm(1)]

    @property
    def number(self):
        return self.operands[0].imm & 0b11111

    @number.setter
    def number(self, new_number):
        assert 0 <= new_number <= 63
        self.operands[0].imm = 0b1100000 | (new_number & 0b11111)

    def lift(self, il, addr):
        il.append(il.trap(self.number))
