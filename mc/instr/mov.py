from . import *


__all__  = ['MovZero8Reg', 'MovImm8Reg', 'MovImm4Reg', 'MovImmReg']
__all__ += ['MovReg8Reg', 'MovRegReg8', 'MovRegReg']
__all__ += ['MovImm8Adr', 'MovImm16Adr', 'MovRegAdr']
__all__ += ['MovdirR0LReg', 'MovdirRegR0L', 'Xchg']
__all__ += ['Mova']
__all__ += ['Stz', 'Stnz', 'Stzx']


class MovZero8Reg(InstrShortOpcode):
    def name(self):
        return 'MOV.B:Z'

    def new_operands(self):
        return [OperZero(), OperR0xDsp8Abs16(offset=0)]


class MovImm8Reg(InstrShortOpcode):
    def name(self):
        return 'MOV.B:S'

    def new_operands(self):
        return [OperImm(1), OperR0xDsp8Abs16(offset=0)]


class MovImm4Reg(HasSize, InstrLongOpcode):
    def name(self):
        return "MOV.{}:Q".format(self.size_suffix())

    def new_operands(self):
        return [
            OperOpcodeImm(self.size(), range(12, 16), sext=True),
            OperRegDsp8Dsp16Abs16(offset=8)
        ]


class MovImmReg(HasSize, InstrLongOpcode):
    def name(self):
        return "MOV.{}:G".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperImm(self.size())]

    def display_operands(self):
        return reversed(self.operands)


class MovReg8Reg(InstrShortOpcode):
    def name(self):
        return 'MOV.B:S'

    def new_operands(self):
        return [OperR0x(offset=2), OperDsp8Abs16(offset=0)]


class MovRegReg8(InstrShortOpcode):
    def name(self):
        return 'MOV.B:S'

    def new_operands(self):
        return [OperR0xR0yDsp8Abs16(offset=0), OperR0x(offset=2)]


class MovRegReg(HasSize, InstrLongOpcode):
    def name(self):
        return "MOV.{}:G".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=12), OperRegDsp8Dsp16Abs16(offset=8)]


class MovImm8Adr(InstrShortOpcode):
    def name(self):
        return 'MOV.B:S'

    def new_operands(self):
        return [OperImm(1), OperAx(offset=3)]


class MovImm16Adr(InstrShortOpcode):
    def name(self):
        return 'MOV.W:S'

    def new_operands(self):
        return [OperImm(2), OperAx(offset=3)]


class MovRegAdr(InstrShortOpcode):
    def name(self):
        return 'MOV.B:S'

    def new_operands(self):
        return [OperAyR0yDsp8Abs16(offset=0), OperAx(offset=2)]


class Movdir(InstrLongOpcode):
    @property
    def dir(self):
        dir1 = "H" if self.opcode & (1 << 13) else "L"
        dir0 = "H" if self.opcode & (1 << 12) else "L"
        return dir0 + dir1

    @dir.setter
    def dir(self, new_dir):
        pass # FIXME


class MovdirR0LReg(Movdir):
    def name(self):
        return "MOV{}".format(self.dir)

    def new_operands(self):
        return [OperReg('R0L'), OperReg8Dsp8Dsp16Abs16(offset=8)]


class MovdirRegR0L(Movdir):
    def name(self):
        return "MOV{}".format(self.dir)

    def new_operands(self):
        return [OperReg8Dsp8Dsp16Abs16(offset=8), OperReg('R0L')]


class Mova(InstrLongOpcode):
    def name(self):
        return 'MOVA'

    def new_operands(self):
        return [OperDsp8Dsp16Abs16(offset=8), OperRxAx(offset=12)]


class Xchg(HasSize, InstrLongOpcode):
    def name(self):
        return "XCHG.{}:G".format(self.size_suffix())

    def new_operands(self):
        return [OperReg8Reg16(offset=12), OperRegDsp8Dsp16Abs16(offset=8)]


class Stz(InstrShortOpcode):
    def name(self):
        return 'STZ'

    def new_operands(self):
        return [OperImm(1), OperR0xDsp8Abs16(offset=0)]


class Stnz(InstrShortOpcode):
    def name(self):
        return 'STNZ'

    def new_operands(self):
        return [OperImm(1), OperR0xDsp8Abs16(offset=0)]


class Stzx(InstrShortOpcode):
    def name(self):
        return 'STZX'

    def new_operands(self):
        return [OperImm(1), OperR0xDsp8Abs16(offset=0), OperImm(1)]

    def display_operands(self):
        return [self.operands[0], self.operands[2], self.operands[1]]
