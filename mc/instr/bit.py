from .. import tables
from . import *


__all__  = ['Bset', 'Bclr', 'Bnot', 'Btst', 'Bntst']
__all__ += ['BsetSB', 'BclrSB', 'BnotSB', 'BtstSB']
__all__ += ['Btstc', 'Btsts']
__all__ += ['Band', 'Bnand', 'Bor', 'Bnor', 'Bxor', 'Bnxor']
__all__ += ['Bmcnd', 'BmcndC']


class Bset(InstrLongOpcode):
    def name(self):
        return 'BSET:G'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Bclr(InstrLongOpcode):
    def name(self):
        return 'BCLR:G'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Bnot(InstrLongOpcode):
    def name(self):
        return 'BNOT:G'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Btst(InstrLongOpcode):
    def name(self):
        return 'BTST:G'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Bntst(InstrLongOpcode):
    def name(self):
        return 'BNTST'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class BsetSB(InstrShortOpcode):
    def name(self):
        return 'BSET:S'

    def new_operands(self):
        return [OperBitBase11SB(offset=0)]


class BclrSB(InstrShortOpcode):
    def name(self):
        return 'BCLR:S'

    def new_operands(self):
        return [OperBitBase11SB(offset=0)]


class BnotSB(InstrShortOpcode):
    def name(self):
        return 'BNOT:S'

    def new_operands(self):
        return [OperBitBase11SB(offset=0)]


class BtstSB(InstrShortOpcode):
    def name(self):
        return 'BTST:S'

    def new_operands(self):
        return [OperBitBase11SB(offset=0)]


class Btstc(InstrLongOpcode):
    def name(self):
        return 'BTSTC'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Btsts(InstrLongOpcode):
    def name(self):
        return 'BTSTS'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Band(InstrLongOpcode):
    def name(self):
        return 'BAND'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Bnand(InstrLongOpcode):
    def name(self):
        return 'BNAND'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Bor(InstrLongOpcode):
    def name(self):
        return 'BOR'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Bnor(InstrLongOpcode):
    def name(self):
        return 'BNOR'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Bxor(InstrLongOpcode):
    def name(self):
        return 'BXOR'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Bnxor(InstrLongOpcode):
    def name(self):
        return 'BNXOR'

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]


class Bmcnd(InstrLongOpcode):
    def name(self):
        return "BM{}".format(self.cond)

    @property
    def cond(self):
        return tables.cnd_bm8[self.cond_code]

    @cond.setter
    def cond(self, new_cond):
        pass # FIXME

    def new_operands(self):
        return [OperBitBase8Base16(offset=8)]

    def length(self):
        return super().length() + 1

    def decode(self, decoder, addr):
        super().decode(decoder, addr)
        self.cond_code = decoder.unsigned_byte()

    def encode(self, encoder, addr):
        super().encode(encoder, addr)
        encoder.unsigned_byte(self.cond_code)


class BmcndC(InstrLongOpcode):
    def name(self):
        return "BM{}".format(self.cond)

    @property
    def cond(self):
        return tables.cnd_bm4[(self.opcode >> 8) & 0b1111]

    @cond.setter
    def cond(self, new_cond):
        pass # FIXME

    def new_operands(self):
        return [OperReg('C')]
