from . import *


__all__ = ['Smovf', 'Smovb', 'Sstr']


class Smovf(InstrLongOpcode, HasSize):
    def name(self):
        return "SMOVF.{}".format(self.size_suffix())


class Smovb(InstrLongOpcode, HasSize):
    def name(self):
        return "SMOVB.{}".format(self.size_suffix())


class Sstr(InstrLongOpcode, HasSize):
    def name(self):
        return "SSTR.{}".format(self.size_suffix())
