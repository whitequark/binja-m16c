from . import *


__all__  = ['AddImmSP', 'AddImm4SP', 'MovIndSPReg', 'MovRegIndSP']
__all__ += ['PushImm', 'PushReg8', 'PushAdr', 'Push', 'Pusha', 'Pushc', 'Pushm']
__all__ += ['PopReg8', 'PopAdr', 'Pop', 'Popc', 'Popm']


class AddImmSP(HasSize, InstrLongOpcode):
    def name(self):
        return "ADD.{}:G".format(self.size_suffix())

    def new_operands(self):
        return [OperImm(self.size()), OperReg('SP')]


class AddImm4SP(InstrLongOpcode):
    def name(self):
        return 'ADD.W:Q'

    def new_operands(self):
        return [OperOpcodeImm(2, range(8, 12), sext=True), OperReg('SP')]


class MovIndSPReg(HasSize, InstrLongOpcode):
    def name(self):
        return "MOV.{}:G".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperIndSP()]

    def display_operands(self):
        return reversed(self.operands)


class MovRegIndSP(HasSize, InstrLongOpcode):
    def name(self):
        return "MOV.{}:G".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperIndSP()]


class PushImm(HasSize, InstrLongOpcode):
    def name(self):
        return "PUSH.{}:G".format(self.size_suffix())

    def new_operands(self):
        return [OperImm(self.size())]


class PushReg8(InstrShortOpcode):
    def name(self):
        return 'PUSH.B:S'

    def new_operands(self):
        return [OperR0x(offset=3)]


class PushAdr(InstrShortOpcode):
    def name(self):
        return 'PUSH.W:S'

    def new_operands(self):
        return [OperAx(offset=3)]


class Push(HasSize, InstrLongOpcode):
    def name(self):
        return "PUSH.{}:G".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]


class Pusha(InstrLongOpcode):
    def name(self):
        return 'PUSHA'

    def new_operands(self):
        return [OperDsp8Dsp16Abs16(offset=8)]


class Pushc(InstrLongOpcode):
    def name(self):
        return 'PUSHC'

    def new_operands(self):
        return [OperCreg(offset=12)]


class Pushm(InstrShortOpcode):
    def name(self):
        return 'PUSHM'

    def new_operands(self):
        return [OperMultiReg(reversed=False)]


class PopReg8(InstrShortOpcode):
    def name(self):
        return 'POP.B:S'

    def new_operands(self):
        return [OperR0x(offset=3)]


class PopAdr(InstrShortOpcode):
    def name(self):
        return 'POP.W:S'

    def new_operands(self):
        return [OperAx(offset=3)]


class Pop(HasSize, InstrLongOpcode):
    def name(self):
        return "POP.{}:G".format(self.size_suffix())

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8)]


class Popc(InstrLongOpcode):
    def name(self):
        return 'POPC'

    def new_operands(self):
        return [OperCreg(offset=12)]


class Popm(InstrShortOpcode):
    def name(self):
        return 'POPM'

    def new_operands(self):
        return [OperMultiReg(reversed=True)]
