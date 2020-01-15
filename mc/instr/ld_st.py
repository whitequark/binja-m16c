from . import *


__all__  = ['Lde', 'LdeA0', 'LdeA1A0', 'Ste', 'SteA0', 'SteA1A0']
__all__ += ['LdcImm', 'LdcReg', 'StcReg', 'StcPc', 'Ldipl']


class Lde(HasSize, InstrLongOpcode):
    def name(self):
        return 'LDE'

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperAbsDataLabel(3)]

    def display_operands(self):
        return reversed(self.operands)


class LdeA0(HasSize, InstrLongOpcode):
    def name(self):
        return 'LDE'

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperDsp20A0()]

    def display_operands(self):
        return reversed(self.operands)


class LdeA1A0(HasSize, InstrLongOpcode):
    def name(self):
        return 'LDE'

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperIndA1A0()]

    def display_operands(self):
        return reversed(self.operands)


class Ste(HasSize, InstrLongOpcode):
    def name(self):
        return 'STE'

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperAbsDataLabel(3)]


class SteA0(HasSize, InstrLongOpcode):
    def name(self):
        return 'STE'

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperDsp20A0()]


class SteA1A0(HasSize, InstrLongOpcode):
    def name(self):
        return 'STE'

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperIndA1A0()]


class LdcImm(InstrLongOpcode):
    def name(self):
        return 'LDC'

    def new_operands(self):
        return [OperImm(2), OperCreg(offset=12)]


class LdcReg(InstrLongOpcode):
    def name(self):
        return 'LDC'

    def new_operands(self):
        return [OperRegDsp8Dsp16Abs16(offset=8), OperCreg(offset=12)]


class StcReg(InstrLongOpcode):
    def name(self):
        return 'STC'

    def new_operands(self):
        return [OperCreg(offset=12), OperRegDsp8Dsp16Abs16(offset=8)]


class StcPc(InstrLongOpcode):
    def name(self):
        return 'STC'

    def new_operands(self):
        return [OperReg('PC'), OperReg16Dsp8Dsp16Dsp20Abs16(offset=8)]


class Ldipl(InstrLongOpcode):
    def name(self):
        return 'LDIPL'

    def new_operands(self):
        return [OperOpcodeImm(1, range(8, 11), sext=False)]
