from . import *


__all__ = ['Ldctx', 'Stctx']


class Ldctx(InstrLongOpcode):
    def name(self):
        return 'LDCTX'

    def new_operands(self):
        return [OperAbs16(), OperAbs20()]


class Stctx(InstrLongOpcode):
    def name(self):
        return 'STCTX'

    def new_operands(self):
        return [OperAbs16(), OperAbs20()]
