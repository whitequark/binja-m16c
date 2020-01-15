from .. import tables
from . import *


__all__  = ['Jmp3', 'Jmp8', 'Jmp16', 'JmpAbs', 'Jmpi', 'JmpiAbs', 'Jmps']
__all__ += ['Jcnd1', 'Jcnd2', 'Adjnz']


class Jmp3(InstrShortOpcode):
    def name(self):
        return 'JMP.S'

    def new_operands(self):
        return [OperOpcodeRelCodeLabel(range(0, 3), sext=False, offset=2)]


class Jmp8(SemaJump, InstrShortOpcode):
    def name(self):
        return 'JMP.B'

    def new_operands(self):
        return [OperRelCodeLabel(1, offset=1)]


class Jmp16(SemaJump, InstrShortOpcode):
    def name(self):
        return 'JMP.W'

    def new_operands(self):
        return [OperRelCodeLabel(2, offset=1)]


class JmpAbs(SemaJump, InstrShortOpcode):
    def name(self):
        return 'JMP.A'

    def new_operands(self):
        return [OperAbsCodeLabel(3)]


class Jmpi(SemaIndJump, InstrLongOpcode):
    def name(self):
        return 'JMPI.W'

    def new_operands(self):
        return [OperReg8Dsp8Dsp16Dsp20Abs16(offset=8)]


class JmpiAbs(SemaIndJump, InstrLongOpcode):
    def name(self):
        return 'JMPI.A'

    def new_operands(self):
        return [OperReg16Dsp8Dsp16Dsp20Abs16(offset=8)]


class Jmps(SemaIndJump, InstrShortOpcode):
    def name(self):
        return 'JMPS'

    def new_operands(self):
        return [OperImm(1)]


class Jcnd1(SemaCondJump, InstrShortOpcode):
    def name(self):
        return "J{}".format(self.cond)

    @property
    def cond(self):
        return tables.cnd_j3[(self.opcode >> 0) & 0b111]

    @cond.setter
    def cond(self, new_cond):
        pass # FIXME

    def new_operands(self):
        return [OperRelCodeLabel(1, offset=1)]


class Jcnd2(SemaCondJump, InstrLongOpcode):
    def name(self):
        return "J{}".format(self.cond)

    @property
    def cond(self):
        return tables.cnd_j4[(self.opcode >> 8) & 0b1111]

    @cond.setter
    def cond(self, new_cond):
        pass # FIXME

    def new_operands(self):
        return [OperRelCodeLabel(1, offset=2)]


class Adjnz(SemaCondJump, HasSize, InstrLongOpcode):
    def name(self):
        return "ADJNZ.{}".format(self.size_suffix())

    def new_operands(self):
        return [
            OperOpcodeImm(self.size(), range(12, 16), sext=True),
            OperRegDsp8Dsp16Abs16(offset=8),
            OperRelCodeLabel(1, offset=2)
        ]

    def target_operand(self):
        return self.operands[2]
