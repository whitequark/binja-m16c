from . import *


__all__  = ['Fclr', 'Fset']


class Fclr(InstrLongOpcode):
    def name(self):
        return 'FCLR'

    def new_operands(self):
        return [OperFlag(offset=12)]


class Fset(InstrLongOpcode):
    def name(self):
        return 'FSET'

    def new_operands(self):
        return [OperFlag(offset=12)]
