from . import *


__all__  = ['Inc', 'Dec', 'IncAdr', 'DecAdr']
__all__ += ['Exts', 'ExtsR0', 'Adcf']
__all__ += ['AddImm4', 'CmpImm4']
__all__ += ['AddImm8', 'CmpImm8', 'SubImm8', 'AndImm8', 'OrImm8']
__all__ += ['AddReg8', 'CmpReg8', 'SubReg8', 'AndReg8', 'OrReg8', 'NotReg8']
__all__ += ['AddImm', 'AdcImm', 'CmpImm', 'SubImm', 'SbbImm']
__all__ += ['AndImm', 'OrImm', 'TstImm', 'XorImm']
__all__ += ['MulImm', 'MuluImm', 'DivImm', 'DivuImm', 'DivxImm']
__all__ += ['AddReg', 'AdcReg', 'CmpReg', 'SubReg', 'SbbReg', 'NegReg', 'AbsReg']
__all__ += ['AndReg', 'OrReg', 'TstReg', 'XorReg', 'NotReg']
__all__ += ['MulReg', 'MuluReg', 'DivReg', 'DivuReg', 'DivxReg']
__all__ += ['Rmpa']
__all__ += ['ShaImm4', 'ShaR1H', 'Sha32Imm4', 'Sha32R1H']
__all__ += ['ShlImm4', 'ShlR1H', 'Shl32Imm4', 'Shl32R1H']
__all__ += ['RotImm4', 'RotR1H', 'Rolc', 'Rorc']


class Inc(InstrShortOpcode):
    def name(self):
        return 'INC.B'

    def new_operands(self):
        return [OperR0xDsp8Abs16(offset=0)]


class Dec(InstrShortOpcode):
    def name(self):
        return 'DEC.B'

    def new_operands(self):
        return [OperR0xDsp8Abs16(offset=0)]


class IncAdr(InstrShortOpcode):
    def name(self):
        return 'INC.W'

    def new_operands(self):
        return [OperAx(offset=3)]


class DecAdr(InstrShortOpcode):
    def name(self):
        return 'DEC.W'

    def new_operands(self):
        return [OperAx(offset=3)]


class Exts(InstrLongOpcode):
    def name(self):
        return 'EXTS.B'

    def new_operands(self):
        return [OperReg8lDsp8Dsp16Abs16(offset=8)]


class ExtsR0(InstrLongOpcode):
    def name(self):
        return 'EXTS.W'

    def new_operands(self):
        return [OperReg('R0')]


class Adcf(HasSize, InstrLongOpcode):
    def name(self):
        return "ADCF.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]


class AddImm4(HasSize, InstrLongOpcode):
    def name(self):
        return "ADD.{}:Q".format(self.size_suffix())

    def new_operands(self):
        return [
            OperOpcodeImm(self.size(), range(12, 16), sext=True),
            OperRegDsp8Dsp16Abs16(offset=8)
        ]


class CmpImm4(HasSize, InstrLongOpcode):
    def name(self):
        return "CMP.{}:Q".format(self.size_suffix())

    def new_operands(self):
        return [
            OperOpcodeImm(self.size(), range(12, 16), sext=True),
            OperRegDsp8Dsp16Abs16(offset=8)
        ]


class AluImm8(InstrShortOpcode):
    def new_operands(self):
        return [OperImm(1), OperR0xDsp8Abs16(offset=0)]


class AddImm8(AluImm8):
    def name(self):
        return 'ADD.B:S'


class CmpImm8(AluImm8):
    def name(self):
        return 'CMP.B:S'


class SubImm8(AluImm8):
    def name(self):
        return 'SUB.B:S'


class AndImm8(AluImm8):
    def name(self):
        return 'AND.B:S'


class OrImm8(AluImm8):
    def name(self):
        return 'OR.B:S'


class AluReg8(InstrShortOpcode):
    def new_operands(self):
        return [OperR0xR0yDsp8Abs16(offset=0), OperR0x(offset=2)]


class AddReg8(AluReg8):
    def name(self):
        return 'ADD.B:S'


class CmpReg8(AluReg8):
    def name(self):
        return 'CMP.B:S'


class SubReg8(AluReg8):
    def name(self):
        return 'SUB.B:S'


class AndReg8(AluReg8):
    def name(self):
        return 'AND.B:S'


class OrReg8(AluReg8):
    def name(self):
        return 'OR.B:S'


class NotReg8(HasSize, InstrShortOpcode):
    def name(self):
        return 'NOT.B:S'

    def new_operands(self):
        return [OperR0xDsp8Abs16(offset=0)]


class AluImm(HasSize, InstrLongOpcode):
    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperImm(self.size())]

    def display_operands(self):
        return reversed(self.operands)


class AddImm(AluImm):
    def name(self):
        return "ADD.{}:G".format(self.size_suffix())


class AdcImm(AluImm):
    def name(self):
        return "ADC.{}".format(self.size_suffix())


class CmpImm(AluImm):
    def name(self):
        return "CMP.{}:G".format(self.size_suffix())


class SubImm(AluImm):
    def name(self):
        return "SUB.{}:G".format(self.size_suffix())


class SbbImm(AluImm):
    def name(self):
        return "SBB.{}".format(self.size_suffix())


class AndImm(AluImm):
    def name(self):
        return "AND.{}:G".format(self.size_suffix())


class OrImm(AluImm):
    def name(self):
        return "OR.{}:G".format(self.size_suffix())


class TstImm(AluImm):
    def name(self):
        return "TST.{}".format(self.size_suffix())


class XorImm(AluImm):
    def name(self):
        return "XOR.{}".format(self.size_suffix())


class MulImm(AluImm):
    def name(self):
        return "MUL.{}".format(self.size_suffix())


class MuluImm(AluImm):
    def name(self):
        return "MULU.{}".format(self.size_suffix())


class DivImm(HasSize, InstrLongOpcode):
    def name(self):
        return "DIV.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperImm(self.size())]


class DivuImm(HasSize, InstrLongOpcode):
    def name(self):
        return "DIVU.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperImm(self.size())]


class DivxImm(HasSize, InstrLongOpcode):
    def name(self):
        return "DIVX.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperImm(self.size())]


class AluReg(HasSize, InstrLongOpcode):
    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=12), OperRegDsp8Dsp16Abs16(offset=8)]


class AddReg(AluReg):
    def name(self):
        return "ADD.{}:G".format(self.size_suffix())


class AdcReg(AluReg):
    def name(self):
        return "ADC.{}".format(self.size_suffix())


class CmpReg(AluReg):
    def name(self):
        return "CMP.{}:G".format(self.size_suffix())


class SubReg(AluReg):
    def name(self):
        return "SUB.{}:G".format(self.size_suffix())


class SbbReg(AluReg):
    def name(self):
        return "SBB.{}".format(self.size_suffix())


class NegReg(HasSize, InstrLongOpcode):
    def name(self):
        return "NEG.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]


class AbsReg(HasSize, InstrLongOpcode):
    def name(self):
        return "ABS.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]


class AndReg(AluReg):
    def name(self):
        return "AND.{}:G".format(self.size_suffix())


class OrReg(AluReg):
    def name(self):
        return "OR.{}:G".format(self.size_suffix())


class TstReg(AluReg):
    def name(self):
        return "TST.{}".format(self.size_suffix())


class XorReg(AluReg):
    def name(self):
        return "XOR.{}".format(self.size_suffix())


class NotReg(HasSize, InstrLongOpcode):
    def name(self):
        return "NOT.{}:G".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]


class MulReg(AluReg):
    def name(self):
        return "MUL.{}".format(self.size_suffix())


class MuluReg(AluReg):
    def name(self):
        return "MULU.{}".format(self.size_suffix())


class DivReg(HasSize, InstrLongOpcode):
    def name(self):
        return "DIV.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]


class DivuReg(HasSize, InstrLongOpcode):
    def name(self):
        return "DIVU.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]


class DivxReg(HasSize, InstrLongOpcode):
    def name(self):
        return "DIVX.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]


class Rmpa(HasSize, InstrLongOpcode):
    def name(self):
        return "RMPA.{}".format(self.size_suffix())


class ShaImm4(HasSize, InstrLongOpcode):
    def name(self):
        return "SHA.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperOpcodeShamt(range(12, 16)), OperRegDsp8Dsp16Abs16(offset=8)]


class Sha32Imm4(InstrLongOpcode):
    def name(self):
        return 'SHA.L'

    def new_operands(self):
        return [OperOpcodeShamt(range(12, 16)), OperRxRy(offset=12)]


class ShaR1H(HasSize, InstrLongOpcode):
    def name(self):
        return "SHA.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperReg('R1H'), OperRegDsp8Dsp16Abs16(offset=8)]


class Sha32R1H(InstrLongOpcode):
    def name(self):
        return 'SHA.L'

    def new_operands(self):
        return [OperReg('R1H'), OperRxRy(offset=12)]


class ShlImm4(HasSize, InstrLongOpcode):
    def name(self):
        return "SHL.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperOpcodeShamt(range(12, 16)), OperRegDsp8Dsp16Abs16(offset=8)]


class Shl32Imm4(InstrLongOpcode):
    def name(self):
        return 'SHL.L'

    def new_operands(self):
        return [OperOpcodeShamt(range(12, 16)), OperRxRy(offset=12)]


class ShlR1H(HasSize, InstrLongOpcode):
    def name(self):
        return "SHL.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperReg('R1H'), OperRegDsp8Dsp16Abs16(offset=8)]


class Shl32R1H(InstrLongOpcode):
    def name(self):
        return 'SHL.L'

    def new_operands(self):
        return [OperReg('R1H'), OperRxRy(offset=12)]


class RotImm4(HasSize, InstrLongOpcode):
    def name(self):
        return "ROT.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperOpcodeShamt(range(12, 16)), OperRegDsp8Dsp16Abs16(offset=8)]


class RotR1H(HasSize, InstrLongOpcode):
    def name(self):
        return "ROT.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperReg('R1H'), OperRegDsp8Dsp16Abs16(offset=8)]


class Rolc(HasSize, InstrLongOpcode):
    def name(self):
        return "ROLC.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]


class Rorc(HasSize, InstrLongOpcode):
    def name(self):
        return "RORC.{}".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]
