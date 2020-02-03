import re
from abc import ABCMeta, abstractmethod
from binaryninja.enums import BranchType

from .. import tables
from ..helpers import *


__all__  = ['Instruction', 'InstrShortOpcode', 'InstrLongOpcode', 'HasSize']
__all__ += ['Operand', 'OperZero', 'OperImm', 'OperOpcodeImm', 'OperOpcodeShamt', 'OperReg']
__all__ += ['OperAbsCodeLabel', 'OperAbsDataLabel', 'OperRelCodeLabel', 'OperOpcodeRelCodeLabel']
__all__ += ['OperR0x', 'OperRxRy', 'OperAx', 'OperRxAx', 'OperDsp8Abs16', 'OperDsp8Dsp16Abs16']
__all__ += ['OperR0xDsp8Abs16', 'OperR0xR0yDsp8Abs16', 'OperAyR0yDsp8Abs16']
__all__ += ['OperRegDsp8Dsp16Abs16', 'OperReg8Dsp8Dsp16Abs16', 'OperReg8lDsp8Dsp16Abs16']
__all__ += ['OperReg8Reg16', 'OperDsp20A0', 'OperIndA1A0', 'OperIndSP', 'OperAbs16', 'OperAbs20']
__all__ += ['OperReg8Dsp8Dsp16Dsp20Abs16', 'OperReg16Dsp8Dsp16Dsp20Abs16']
__all__ += ['OperBitBase8Base16', 'OperBitBase11SB', 'OperMultiReg', 'OperFlag', 'OperCreg']
__all__ += ['SemaJump', 'SemaIndJump', 'SemaCondJump', 'SemaCall', 'SemaIndCall', 'SemaReturn']
__all__ += ['SemaTrap']


class Instruction(metaclass=ABCMeta):
    opcodes = {}

    show_suffix = True

    def __new__(cls, decoder=None):
        if decoder is None:
            return object.__new__(cls)
        else:
            entry  = cls.opcodes
            offset = 0
            while isinstance(entry, dict):
                byte   = decoder.peek(offset // 8)
                nibble = (byte >> (4 - (offset % 8))) & 0xf
                entry  = entry[nibble]
                offset += 4
            return object.__new__(entry)

    def new_operands(self):
        return []

    def name(self):
        return 'unimplemented'

    @abstractmethod
    def length(self):
        return sum(operand.length() for operand in self.operands)

    @abstractmethod
    def decode(self, decoder, addr):
        self.operands = self.new_operands()
        for operand in self.operands:
            operand.decode(self.opcode, decoder, addr)

    @abstractmethod
    def encode(self, encoder, addr):
        for operand in self.operands:
            self.opcode = operand.encode(self.opcode, encoder, addr)

    def analyze(self, info, addr):
        info.length += self.length()
        for operand in self.operands:
            operand.analyze(info, addr)

    def display_name(self):
        if self.show_suffix:
            return self.name()
        else:
            return re.sub(r":[GQSZ]$", "", self.name())

    def display_operands(self):
        return self.operands

    def render(self, addr):
        display_name = self.display_name()
        tokens = asm(('instr', display_name))
        opsep  = ' ' * ((10 if self.show_suffix else 8) - len(display_name))
        for operand in self.display_operands():
            tokens += asm(('opsep', opsep))
            tokens += operand.render(addr)
            opsep   = ', '
        return tokens

    def lift(self, il, addr):
        il.append(il.unimplemented())


class InstrShortOpcode(Instruction):
    def length(self):
        return 1 + super().length()

    def decode(self, decoder, addr):
        self.opcode = decoder.unsigned_byte()
        super().decode(decoder, addr)

    def encode(self, encoder, addr):
        encoder.unsigned_byte(self.opcode)
        super().encode(encoder, addr)


class InstrLongOpcode(Instruction):
    def length(self):
        return 2 + super().length()

    def decode(self, decoder, addr):
        self.opcode = decoder.unsigned_word()
        super().decode(decoder, addr)

    def encode(self, encoder, addr):
        encoder.unsigned_word(self.opcode)
        super().encode(encoder, addr)


class HasSize(Instruction):
    def size(self):
        if self.opcode & 1:
            return 2
        else:
            return 1

    def size_suffix(self):
        size = self.size()
        if size == 1:
            return "B"
        if size == 2:
            return "W"
        assert False


class Operand(metaclass=ABCMeta):
    def length(self):
        return 0

    def decode(self, opcode, decoder, addr):
        pass

    def encode(self, opcode, encoder, addr):
        return opcode

    def analyze(self, info, addr):
        pass

    @abstractmethod
    def render(self, addr):
        pass


class OperZero(Operand):
    def render(self, addr):
        return asm(('int', "#0", 0))


class OperImm(Operand):
    def __init__(self, size):
        self.size = size

    def length(self):
        return self.size

    def decode(self, opcode, decoder, addr):
        self.imm = decoder.unsigned(self.size)

    def encode(self, opcode, encoder, addr):
        encoder.unsigned(self.imm, self.size)
        return opcode

    def render(self, addr):
        return asm(('int', "#{:0{}X}h".format(self.imm, self.size * 2), self.imm))


class OperOpcodeImm(Operand):
    def __init__(self, size, bits, *, sext):
        self.size = size
        self.bits = bits
        self.sext = sext

    def decode(self, opcode, decoder, addr):
        self.imm = get_bits(opcode, self.bits, sext=self.sext)
        self.imm &= ((1 << (self.size * 8)) - 1)

    def encode(self, opcode, encoder, addr):
        return opcode # FIXME

    def render(self, addr):
        return asm(('int', "#{:0{}X}h".format(self.imm, self.size * 2), self.imm))


class OperOpcodeShamt(Operand):
    def __init__(self, bits):
        self.bits = bits

    def decode(self, opcode, decoder, addr):
        imm4 = get_bits(opcode, self.bits, sext=True)
        if imm4 >= 0:
            self.shamt = 1 + imm4
        else:
            self.shamt = imm4

    def encode(self, opcode, encoder, addr):
        return opcode # FIXME

    def render(self, addr):
        return asm(('int', "#{:d}".format(self.shamt), self.shamt))


class OperReg(Operand):
    def __init__(self, name):
        self.reg = name

    def render(self, addr):
        return asm(('reg', self.reg))


class OperAbsLabel(Operand):
    kind = 'addr'

    def __init__(self, size):
        self.size = size

    def length(self):
        return self.size

    def decode(self, opcode, decoder, addr):
        self.target = decoder.unsigned(self.size)

    def encode(self, opcode, encoder, addr):
        encoder.unsigned(self.target, self.size)
        return opcode

    def render(self, addr):
        target = self.target
        return asm(('codeSym', "{:05X}h".format(self.target), self.target))


class OperAbsCodeLabel(OperAbsLabel):
    kind = 'codeSym'


class OperAbsDataLabel(OperAbsLabel):
    kind = 'dataSym'


class OperRelCodeLabel(Operand):
    def __init__(self, size, *, offset):
        self.size   = size
        self.offset = offset

    def length(self):
        return self.size

    def decode(self, opcode, decoder, addr):
        self.target = decoder.signed(self.size) + (addr + self.offset)

    def encode(self, opcode, encoder, addr):
        encoder.signed(self.target - (addr + self.offset), self.size)
        return opcode

    def render(self, addr):
        return asm(('codeSym', "{:05X}h".format(self.target), self.target))


class OperOpcodeRelCodeLabel(Operand):
    def __init__(self, bits, *, sext, offset):
        self.bits   = bits
        self.sext   = sext
        self.offset = offset

    def decode(self, opcode, decoder, addr):
        self.target = get_bits(opcode, self.bits, sext=self.sext) + (addr + self.offset)

    def encode(self, opcode, encoder, addr):
        return opcode # FIXME

    def render(self, addr):
        return asm(('codeSym', "{:05X}h".format(self.target), self.target))


class OperRegIndAbs(Operand):
    config   = None
    use_size = False

    def __init__(self, *, offset=None):
        self.offset = offset
        self.mode   = None

    def length(self):
        if self.mode is None:
            return
        elif self.mode in ('R0L', 'R0H', 'R0', 'R2', 'R2R0', 'R1L', 'R1H', 'R1', 'R3', 'R3R1',
                           'A0', 'A1', 'A1A0', '[A0]', '[A1]', '[A1A0]'):
            return 0
        elif self.mode in ('dsp:8[A0]', 'dsp:8[A1]', 'dsp:8[SB]', 'dsp:8[FB]', 'dsp:8[SP]'):
            return 1
        elif self.mode in ('dsp:16[A0]', 'dsp:16[A1]', 'dsp:16[SB]', 'abs16'):
            return 2
        elif self.mode in ('dsp:20[A0]', 'dsp:20[A1]', 'abs20'):
            return 3
        else:
            assert False

    def decode(self, opcode, decoder, addr):
        if isinstance(self.config, str):
            self.mode = self.config
        else:
            mode_table, mode_mask = self.config
            if self.use_size:
                mode_table = mode_table[(opcode >> 0) & 1]
            self.mode = mode_table[(opcode >> self.offset) & mode_mask]
        if self.mode in ('R0L', 'R0H', 'R0', 'R2', 'R2R0', 'R1L', 'R1H', 'R1', 'R3', 'R3R1',
                         'A0', 'A1', 'A1A0', '[A0]', '[A1]', '[A1A0]'):
            pass
        elif self.mode in ('dsp:8[A0]', 'dsp:8[A1]', 'dsp:8[SB]'):
            self.dsp8 = decoder.unsigned_byte()
        elif self.mode in ('dsp:8[FB]', 'dsp:8[SP]'):
            self.dsp8 = decoder.signed_byte()
        elif self.mode in ('dsp:16[A0]', 'dsp:16[A1]', 'dsp:16[SB]'):
            self.dsp16 = decoder.unsigned_word()
        elif self.mode == 'abs16':
            self.abs16 = decoder.unsigned_word()
        elif self.mode in ('dsp:20[A0]', 'dsp:20[A1]'):
            self.dsp20 = decoder.unsigned_triple()
        elif self.mode == 'abs20':
            self.abs20 = decoder.unsigned_triple()
        else:
            assert False, "unknown mode {}".format(self.mode)

    def encode(self, opcode, encoder, addr):
        if self.mode in ('R0L', 'R0H', 'R0', 'R2', 'R2R0', 'R1L', 'R1H', 'R1', 'R3', 'R3R1',
                         'A0', 'A1', 'A1A0', '[A0]', '[A1]', '[A1A0]'):
            pass
        elif self.mode in ('dsp:8[A0]', 'dsp:8[A1]', 'dsp:8[SB]'):
            encoder.unsigned_byte(self.dsp8)
        elif self.mode in ('dsp:8[FB]', 'dsp:8[SP]'):
            encoder.signed_byte(self.dsp8)
        elif self.mode in ('dsp:16[A0]', 'dsp:16[A1]', 'dsp:16[SB]'):
            encoder.unsigned_word(self.dsp16)
        elif self.mode == 'abs16':
            encoder.unsigned_word(self.abs16)
        elif self.mode in ('dsp:20[A0]', 'dsp:20[A1]'):
            encoder.unsigned_triple(self.dsp20)
        elif self.mode == 'abs20':
            encoder.unsigned_triple(self.abs20)
        else:
            assert False
        return opcode # FIXME

    def render(self, addr):
        if self.mode in ('R0L', 'R0H', 'R0', 'R2', 'R2R0', 'R1L', 'R1H', 'R1', 'R3', 'R3R1',
                         'A0', 'A1', 'A1A0'):
            return asm(('reg', self.mode))
        if self.mode in ('[A0]', '[A1]', '[A1A0]'):
            return asm(
                ('beginMem', '['),
                ('reg', self.mode[1:-1]),
                ('endMem', ']'),
            )
        elif self.mode in ('dsp:8[A0]', 'dsp:8[A1]', 'dsp:8[SB]'):
            return asm(
                ('int', "{:02X}h".format(self.dsp8), self.dsp8),
                ('beginMem', '['),
                ('reg', self.mode[-3:-1]),
                ('endMem', ']'),
            )
        elif self.mode in ('dsp:8[FB]', 'dsp:8[SP]'):
            return asm(
                ('int', "{:+d}".format(self.dsp8), self.dsp8),
                ('beginMem', '['),
                ('reg', self.mode[-3:-1]),
                ('endMem', ']'),
            )
        elif self.mode in ('dsp:16[A0]', 'dsp:16[A1]', 'dsp:16[SB]'):
            return asm(
                ('int', "{:04X}h".format(self.dsp16), self.dsp16),
                ('beginMem', '['),
                ('reg', self.mode[-3:-1]),
                ('endMem', ']'),
            )
        elif self.mode == 'abs16':
            return asm(('dataSym', "{:05X}h".format(self.abs16), self.abs16))
        elif self.mode in ('dsp:20[A0]', 'dsp:20[A1]'):
            return asm(
                ('addr', "{:05X}h".format(self.dsp20), self.dsp20),
                ('beginMem', '['),
                ('reg', self.mode[-3:-1]),
                ('endMem', ']'),
            )
        elif self.mode == 'abs20':
            return asm(('dataSym', "{:05X}h".format(self.abs20), self.abs20))
        else:
            assert False


class OperR0x(OperRegIndAbs):
    config = (tables.r0x, 0b1)


class OperRxRy(OperRegIndAbs):
    config = (tables.rx_ry, 0b1)


class OperAx(OperRegIndAbs):
    config = (tables.ax, 0b1)


class OperRxAx(OperRegIndAbs):
    config = (tables.rx_ax, 0b111)


class OperDsp8Abs16(OperRegIndAbs):
    config = (tables.dsp8_abs16, 0b11)


class OperDsp8Dsp16Abs16(OperRegIndAbs):
    config = (tables.dsp8_dsp16_abs16, 0b1111)


class OperR0xDsp8Abs16(OperRegIndAbs):
    config = (tables.r0x_dsp8_abs16, 0b111)


class OperR0xR0yDsp8Abs16(OperRegIndAbs):
    config = (tables.r0x_r0y_dsp8_abs16, 0b111)


class OperAyR0yDsp8Abs16(OperRegIndAbs):
    config = (tables.ay_r0y_dsp8_abs16, 0b111)


class OperRegDsp8Dsp16Abs16(OperRegIndAbs):
    config = (tables.reg_dsp8_dsp16_abs16, 0b1111)
    use_size = True


class OperReg8Reg16(OperRegIndAbs):
    config = (tables.reg8_reg16, 0b11)
    use_size = True


class OperDsp20A0(OperRegIndAbs):
    config = 'dsp:20[A0]'


class OperIndA1A0(OperRegIndAbs):
    config = '[A1A0]'


class OperIndSP(OperRegIndAbs):
    config = 'dsp:8[SP]'


class OperAbs16(OperRegIndAbs):
    config = 'abs16'


class OperAbs20(OperRegIndAbs):
    config = 'abs20'


class OperReg8Dsp8Dsp16Abs16(OperRegIndAbs):
    config = (tables.reg8_dsp8_dsp16_abs16, 0b1111)


class OperReg8lDsp8Dsp16Abs16(OperRegIndAbs):
    config = (tables.reg8l_dsp8_dsp16_abs16, 0b1111)


class OperReg8Dsp8Dsp16Dsp20Abs16(OperRegIndAbs):
    config = (tables.reg8_dsp8_dsp16_dsp20_abs16, 0b1111)


class OperReg16Dsp8Dsp16Dsp20Abs16(OperRegIndAbs):
    config = (tables.reg16_dsp8_dsp16_dsp20_abs16, 0b1111)


class OperBitIndAbs(Operand):
    config = None

    def __init__(self, *, offset=None):
        self.offset = offset
        self.mode   = None

    def length(self):
        if self.mode is None:
            return
        elif self.mode in ('bit,R0', 'bit,R1', 'bit,R2', 'bit,R3', 'bit,A0', 'bit,A1'):
            return 1
        elif self.mode in ('[A0]', '[A1]'):
            return 0
        elif self.mode in ('base:8[A0]', 'base:8[A1]', 'bit,base:8[SB]', 'bit,base:8[FB]',
                           'bit,base:11[SB]'):
            return 1
        elif self.mode in ('base:16[A0]', 'base:16[A1]', 'bit,base:16[SB]', 'bit,base:16'):
            return 2
        else:
            assert False

    def decode(self, opcode, decoder, addr):
        if isinstance(self.config, str):
            self.mode = self.config
        else:
            mode_table, mode_mask = self.config
            self.mode = mode_table[(opcode >> self.offset) & mode_mask]
        if self.mode in ('bit,R0', 'bit,R1', 'bit,R2', 'bit,R3', 'bit,A0', 'bit,A1'):
            self.bit = decoder.unsigned_byte()
        elif self.mode in ('[A0]', '[A1]'):
            pass
        elif self.mode in ('base:8[A0]', 'base:8[A1]', 'bit,base:8[SB]', 'bit,base:8[FB]'):
            dsp8 = decoder.unsigned_byte()
            if self.mode in ('bit,base:8[SB]', 'bit,base:8[FB]'):
                self.bit = dsp8 & 0x7
                self.base = dsp8 >> 3
            else:
                self.base = dsp8
        elif self.mode == 'bit,base:11[SB]':
            self.bit = opcode & 0b111
            self.base = decoder.unsigned_byte()
        elif self.mode in ('base:16[A0]', 'base:16[A1]', 'bit,base:16[SB]', 'bit,base:16'):
            dsp16 = decoder.unsigned_word()
            if self.mode in ('bit,base:16[SB]', 'bit,base:16'):
                self.bit = dsp16 & 0x7
                self.base = dsp16 >> 3
            else:
                self.base = dsp16
        else:
            assert False

    def encode(self, opcode, encoder, addr):
        if self.mode in ('bit,R0', 'bit,R1', 'bit,R2', 'bit,R3', 'bit,A0', 'bit,A1'):
            encoder.unsigned_byte(self.bit)
        elif self.mode in ('[A0]', '[A1]'):
            pass
        elif self.mode in ('base:8[A0]', 'base:8[A1]', 'bit,base:8[SB]', 'bit,base:8[FB]'):
            if self.mode in ('bit,base:8[SB]', 'bit,base:8[FB]'):
                encoder.unsigned_byte((self.base << 3) | self.bit)
            else:
                encoder.unsigned_byte(self.base)
        elif self.mode == 'bit,base:11[SB]':
            # FIXME self.bit
            encoder.unsigned_byte(self.base)
        elif self.mode in ('base:16[A0]', 'base:16[A1]', 'bit,base:16[SB]', 'bit,base:16'):
            if self.mode in ('bit,base:16[SB]', 'bit,base:16'):
                encoder.unsigned_word((self.base << 3) | self.bit)
            else:
                encoder.unsigned_word(self.base)
        else:
            assert False
        return opcode # FIXME

    def render(self, addr):
        if self.mode in ('bit,R0', 'bit,R1', 'bit,R2', 'bit,R3', 'bit,A0', 'bit,A1'):
            return asm(
                ('int', "{:d}".format(self.bit), self.bit),
                ('opsep', ', '),
                ('reg', self.mode[-2:])
            )
        elif self.mode in ('[A0]', '[A1]'):
            return asm(
                ('beginMem', '['),
                ('reg', self.mode[-3:-1]),
                ('endMem', ']'),
            )
        elif self.mode in ('base:8[A0]', 'base:8[A1]'):
            return asm(
                ('int', "{:02X}h".format(self.base), self.base),
                ('beginMem', '['),
                ('reg', self.mode[-3:-1]),
                ('endMem', ']'),
            )
        elif self.mode in ('bit,base:8[SB]', 'bit,base:8[FB]', 'bit,base:11[SB]'):
            return asm(
                ('int', "{:d}".format(self.bit), self.bit),
                ('opsep', ', '),
                ('int', "{:02X}h".format(self.base), self.base),
                ('beginMem', '['),
                ('reg', self.mode[-3:-1]),
                ('endMem', ']'),
            )
        elif self.mode in ('base:16[A0]', 'base:16[A1]'):
            return asm(
                ('int', "{:04X}h".format(self.base), self.base),
                ('beginMem', '['),
                ('reg', self.mode[-3:-1]),
                ('endMem', ']'),
            )
        elif self.mode == 'bit,base:16[SB]':
            return asm(
                ('int', "{:d}".format(self.bit), self.bit),
                ('opsep', ', '),
                ('int', "{:04X}h".format(self.base), self.base),
                ('beginMem', '['),
                ('reg', self.mode[-3:-1]),
                ('endMem', ']'),
            )
        elif self.mode == 'bit,base:16':
            return asm(
                ('int', "{:d}".format(self.bit), self.bit),
                ('opsep', ', '),
                ('dataSym', "{:05X}h".format(self.base), self.base)
            )
        else:
            assert False


class OperBitBase8Base16(OperBitIndAbs):
    config = (tables.bit_base8_base16, 0b1111)


class OperBitBase11SB(OperBitIndAbs):
    config = 'bit,base:11[SB]'


class OperMultiReg(Operand):
    def __init__(self, reversed):
        self.reversed = reversed

    def length(self):
        return 1

    def decode(self, opcode, decoder, addr):
        self.reg_mask = decoder.unsigned_byte()

    def encode(self, opcode, encoder, addr):
        encoder.unsigned_byte(self.reg_mask)
        return opcode

    def render(self, addr):
        register_list = ['R0', 'R1', 'R2', 'R3', 'A0', 'A1', 'SB', 'FB']
        if self.reversed:
            register_list = reversed(register_list)
        tokens = []
        for index, reg in enumerate(register_list):
            if self.reg_mask & (1 << index):
                if tokens:
                    tokens += asm(('opsep', ', '))
                tokens += asm(('reg', reg))
        return tokens


class OperFlag(Operand):
    def __init__(self, offset):
        self.offset = offset

    def decode(self, opcode, decoder, addr):
        self.flag = tables.flag[(opcode >> self.offset) & 0b111]

    def encode(self, opcode, encoder, addr):
        return opcode # FIXME

    def render(self, addr):
        return asm(('reg', self.flag))


class OperCreg(Operand):
    def __init__(self, offset):
        self.offset = offset

    def decode(self, opcode, decoder, addr):
        self.reg = tables.creg[(opcode >> self.offset) & 0b111]

    def encode(self, opcode, encoder, addr):
        return opcode # FIXME

    def render(self, addr):
        return asm(('reg', self.reg))


class HasTarget:
    def target_operand(self):
        return self.operands[0]


class HasLabel(HasTarget):
    @property
    def target(self):
        return self.target_operand().target

    @target.setter
    def target(self, value):
        self.target_operand().target = value


class SemaJump(HasLabel):
    def analyze(self, info, addr):
        super().analyze(info, addr)
        info.add_branch(BranchType.UnconditionalBranch, self.target)


class SemaIndJump(HasTarget):
    def analyze(self, info, addr):
        super().analyze(info, addr)
        info.add_branch(BranchType.IndirectBranch)

    def lift(self, il, addr):
        il.append(il.unimplemented())
        il.append(il.undefined())


class SemaCondJump(HasLabel):
    def analyze(self, info, addr):
        super().analyze(info, addr)
        info.add_branch(BranchType.TrueBranch, self.target)
        info.add_branch(BranchType.FalseBranch, addr + self.length())


class SemaCall(HasLabel):
    def analyze(self, info, addr):
        super().analyze(info, addr)
        info.add_branch(BranchType.CallDestination, self.target)


class SemaIndCall(HasTarget):
    def analyze(self, info, addr):
        super().analyze(info, addr)
        # Binja has no branch type for indirect calls (yet?)


class SemaReturn:
    def analyze(self, info, addr):
        super().analyze(info, addr)
        info.add_branch(BranchType.FunctionReturn)

    def lift(self, il, addr):
        il.append(il.unimplemented())
        il.append(il.undefined())


class SemaTrap:
    def analyze(self, info, addr):
        super().analyze(info, addr)
        info.add_branch(BranchType.UnresolvedBranch)
