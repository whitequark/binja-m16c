from . import *


__all__  = ['DadcImm8', 'DadcImm16', 'DadcReg8', 'DadcReg16']
__all__ += ['DaddImm8', 'DaddImm16', 'DaddReg8', 'DaddReg16']
__all__ += ['DsbbImm8', 'DsbbImm16', 'DsbbReg8', 'DsbbReg16']
__all__ += ['DsubImm8', 'DsubImm16', 'DsubReg8', 'DsubReg16']


class DadcImm8(InstrLongOpcode):
    def name(self):
        return 'DADC.B'

    def new_operands(self):
        return [OperImm(1), OperReg('R0L')]


class DadcImm16(InstrLongOpcode):
    def name(self):
        return 'DADC.W'

    def new_operands(self):
        return [OperImm(1), OperReg('R0')]


class DadcReg8(InstrLongOpcode):
    def name(self):
        return 'DADC.B'

    def new_operands(self):
        return [OperReg('R0H'), OperReg('R0L')]


class DadcReg16(InstrLongOpcode):
    def name(self):
        return 'DADC.W'

    def new_operands(self):
        return [OperReg('R1'), OperReg('R0')]


class DaddImm8(InstrLongOpcode):
    def name(self):
        return 'DADD.B'

    def new_operands(self):
        return [OperImm(1), OperReg('R0L')]


class DaddImm16(InstrLongOpcode):
    def name(self):
        return 'DADD.W'

    def new_operands(self):
        return [OperImm(1), OperReg('R0')]


class DaddReg8(InstrLongOpcode):
    def name(self):
        return 'DADD.B'

    def new_operands(self):
        return [OperReg('R0H'), OperReg('R0L')]


class DaddReg16(InstrLongOpcode):
    def name(self):
        return 'DADD.W'

    def new_operands(self):
        return [OperReg('R1'), OperReg('R0')]


class DsbbImm8(InstrLongOpcode):
    def name(self):
        return 'DSBB.B'

    def new_operands(self):
        return [OperImm(1), OperReg('R0L')]


class DsbbImm16(InstrLongOpcode):
    def name(self):
        return 'DSBB.W'

    def new_operands(self):
        return [OperImm(1), OperReg('R0')]


class DsbbReg8(InstrLongOpcode):
    def name(self):
        return 'DSBB.B'

    def new_operands(self):
        return [OperReg('R0H'), OperReg('R0L')]


class DsbbReg16(InstrLongOpcode):
    def name(self):
        return 'DSBB.W'

    def new_operands(self):
        return [OperReg('R1'), OperReg('R0')]


class DsubImm8(InstrLongOpcode):
    def name(self):
        return 'DSUB.B'

    def new_operands(self):
        return [OperImm(1), OperReg('R0L')]


class DsubImm16(InstrLongOpcode):
    def name(self):
        return 'DSUB.W'

    def new_operands(self):
        return [OperImm(1), OperReg('R0')]


class DsubReg8(InstrLongOpcode):
    def name(self):
        return 'DSUB.B'

    def new_operands(self):
        return [OperReg('R0H'), OperReg('R0L')]


class DsubReg16(InstrLongOpcode):
    def name(self):
        return 'DSUB.W'

    def new_operands(self):
        return [OperReg('R1'), OperReg('R0')]
