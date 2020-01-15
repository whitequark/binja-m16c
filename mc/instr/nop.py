from . import *


__all__ = ['Nop', 'Wait']


class Nop(InstrShortOpcode):
    def name(self):
        return 'NOP'

    def lift(self, il, addr):
        il.append(il.nop())


class Wait(InstrShortOpcode):
    def name(self):
        return 'WAIT'
