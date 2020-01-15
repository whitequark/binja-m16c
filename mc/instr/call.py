from . import *


__all__  = ['Jsr16', 'JsrAbs', 'Jsri', 'JsriAbs', 'Jsrs']
__all__ += ['Enter', 'Exitd', 'Rts', 'Reit']


class Jsr16(SemaCall, InstrShortOpcode):
    def name(self):
        return 'JSR.W'

    def new_operands(self):
        return [OperRelCodeLabel(2, offset=1)]


class JsrAbs(SemaCall, InstrShortOpcode):
    def name(self):
        return 'JSR.A'

    def new_operands(self):
        return [OperAbsCodeLabel(3)]


class Jsri(SemaIndCall, InstrLongOpcode):
    def name(self):
        return 'JSRI.W'

    def new_operands(self):
        return [OperReg8Dsp8Dsp16Dsp20Abs16(offset=8)]


class JsriAbs(SemaIndCall, InstrLongOpcode):
    def name(self):
        return 'JSRI.A'

    def new_operands(self):
        return [OperReg16Dsp8Dsp16Dsp20Abs16(offset=8)]


class Jsrs(SemaIndCall, InstrShortOpcode):
    def name(self):
        return 'JSRS'

    def new_operands(self):
        return [OperImm(1)]


class Enter(InstrLongOpcode):
    def name(self):
        return 'ENTER'

    def new_operands(self):
        return [OperImm(1)]


class Exitd(SemaReturn, InstrLongOpcode):
    def name(self):
        return 'EXITD'


class Rts(SemaReturn, InstrShortOpcode):
    def name(self):
        return 'RTS'


class Reit(SemaReturn, InstrShortOpcode):
    def name(self):
        return 'REIT'
