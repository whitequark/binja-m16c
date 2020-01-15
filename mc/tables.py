from binaryninja.enums import LowLevelILFlagCondition


__all__ = []


r0x = {
    0b0: 'R0L',
    0b1: 'R0H',
}

rx_ry = {
    0b0: 'R2R0',
    0b1: 'R3R1',
}

ax = {
    0b0: 'A0',
    0b1: 'A1',
}

rx_ax = {
    0b000: 'R0',
    0b001: 'R1',
    0b010: 'R2',
    0b011: 'R3',
    0b100: 'A0',
    0b101: 'A1',
}

dsp8_abs16 = {
    0b01: 'dsp:8[SB]',
    0b10: 'dsp:8[FB]',
    0b11: 'abs16',
}

r0x_dsp8_abs16 = {
    0b011: 'R0H',
    0b100: 'R0L',
    0b101: 'dsp:8[SB]',
    0b110: 'dsp:8[FB]',
    0b111: 'abs16'
}

r0x_r0y_dsp8_abs16 = {
    0b000: 'R0H',
    0b001: 'dsp:8[SB]',
    0b010: 'dsp:8[FB]',
    0b011: 'abs16',
    0b100: 'R0L',
    0b101: 'dsp:8[SB]',
    0b110: 'dsp:8[FB]',
    0b111: 'abs16'
}

ay_r0y_dsp8_abs16 = {
    0b000: 'R0L',
    0b001: 'dsp:8[SB]',
    0b010: 'dsp:8[FB]',
    0b011: 'abs16',
    0b100: 'R0H',
    0b101: 'dsp:8[SB]',
    0b110: 'dsp:8[FB]',
    0b111: 'abs16',
}

dsp8_dsp16_abs16 = {
    0b1000: 'dsp:8[A0]',
    0b1001: 'dsp:8[A1]',
    0b1010: 'dsp:8[SB]',
    0b1011: 'dsp:8[FB]',
    0b1100: 'dsp:16[A0]',
    0b1101: 'dsp:16[A1]',
    0b1110: 'dsp:16[SB]',
    0b1111: 'abs16',
}

reg8_reg16 = {
    0b0: {
        0b0000: 'R0L',
        0b0001: 'R0H',
        0b0010: 'R1L',
        0b0011: 'R1H',
    },
    0b1: {
        0b0000: 'R0',
        0b0001: 'R1',
        0b0010: 'R2',
        0b0011: 'R3',
    }
}

reg_dsp8_dsp16_abs16 = {
    0b0: {
        0b0000: 'R0L',
        0b0001: 'R0H',
        0b0010: 'R1L',
        0b0011: 'R1H',
        0b0100: 'A0',
        0b0101: 'A1',
        0b0110: '[A0]',
        0b0111: '[A1]',
        0b1000: 'dsp:8[A0]',
        0b1001: 'dsp:8[A1]',
        0b1010: 'dsp:8[SB]',
        0b1011: 'dsp:8[FB]',
        0b1100: 'dsp:16[A0]',
        0b1101: 'dsp:16[A1]',
        0b1110: 'dsp:16[SB]',
        0b1111: 'abs16',
    },
    0b1: {
        0b0000: 'R0',
        0b0001: 'R1',
        0b0010: 'R2',
        0b0011: 'R3',
        0b0100: 'A0',
        0b0101: 'A1',
        0b0110: '[A0]',
        0b0111: '[A1]',
        0b1000: 'dsp:8[A0]',
        0b1001: 'dsp:8[A1]',
        0b1010: 'dsp:8[SB]',
        0b1011: 'dsp:8[FB]',
        0b1100: 'dsp:16[A0]',
        0b1101: 'dsp:16[A1]',
        0b1110: 'dsp:16[SB]',
        0b1111: 'abs16',
    }
}

reg8_dsp8_dsp16_abs16 = {
    0b0000: 'R0L',
    0b0001: 'R0H',
    0b0010: 'R1L',
    0b0011: 'R1H',
    0b0110: '[A0]',
    0b0111: '[A1]',
    0b1000: 'dsp:8[A0]',
    0b1001: 'dsp:8[A1]',
    0b1010: 'dsp:8[SB]',
    0b1011: 'dsp:8[FB]',
    0b1100: 'dsp:20[A0]',
    0b1101: 'dsp:20[A1]',
    0b1110: 'dsp:16[SB]',
    0b1111: 'abs16',
}

reg8l_dsp8_dsp16_abs16 = {
    0b0000: 'R0L',
    0b0010: 'R1L',
    0b0110: '[A0]',
    0b0111: '[A1]',
    0b1000: 'dsp:8[A0]',
    0b1001: 'dsp:8[A1]',
    0b1010: 'dsp:8[SB]',
    0b1011: 'dsp:8[FB]',
    0b1100: 'dsp:20[A0]',
    0b1101: 'dsp:20[A1]',
    0b1110: 'dsp:16[SB]',
    0b1111: 'abs16',
}

reg8_dsp8_dsp16_dsp20_abs16 = {
    0b0000: 'R0',
    0b0001: 'R1',
    0b0010: 'R2',
    0b0011: 'R3',
    0b0100: 'A0',
    0b0101: 'A1',
    0b0110: '[A0]',
    0b0111: '[A1]',
    0b1000: 'dsp:8[A0]',
    0b1001: 'dsp:8[A1]',
    0b1010: 'dsp:8[SB]',
    0b1011: 'dsp:8[FB]',
    0b1100: 'dsp:20[A0]',
    0b1101: 'dsp:20[A1]',
    0b1110: 'dsp:16[SB]',
    0b1111: 'abs16',
}

reg16_dsp8_dsp16_dsp20_abs16 = {
    0b0000: 'R2R0',
    0b0001: 'R3R1',
    0b0100: 'A1A0',
    0b0110: '[A0]',
    0b0111: '[A1]',
    0b1000: 'dsp:8[A0]',
    0b1001: 'dsp:8[A1]',
    0b1010: 'dsp:8[SB]',
    0b1011: 'dsp:8[FB]',
    0b1100: 'dsp:20[A0]',
    0b1101: 'dsp:20[A1]',
    0b1110: 'dsp:16[SB]',
    0b1111: 'abs16',
}

bit_base8_base16 = {
    0b0000: 'bit,R0',
    0b0001: 'bit,R1',
    0b0010: 'bit,R2',
    0b0011: 'bit,R3',
    0b0100: 'bit,A0',
    0b0101: 'bit,A1',
    0b0110: '[A0]',
    0b0111: '[A1]',
    0b1000: 'base:8[A0]',
    0b1001: 'base:8[A1]',
    0b1010: 'bit,base:8[SB]',
    0b1011: 'bit,base:8[FB]',
    0b1100: 'base:16[A0]',
    0b1101: 'base:16[A1]',
    0b1110: 'bit,base:16[SB]',
    0b1111: 'bit,base:16',
}

flag = {
    0b000: 'C',
    0b001: 'D',
    0b010: 'Z',
    0b011: 'S',
    0b100: 'B',
    0b101: 'O',
    0b110: 'I',
    0b111: 'U',
}

creg = {
    0b001: 'INTBL',
    0b010: 'INTBH',
    0b011: 'FLG',
    0b100: 'ISP',
    0b101: 'USP',
    0b110: 'SB',
    0b111: 'FB',
}

cnd_j3 = {
    0b000: 'GEU', # C
    0b001: 'GTU',
    0b010: 'EQ', # Z
    0b011: 'N',
    0b100: 'LTU', # NC
    0b101: 'LEU',
    0b110: 'NE', # NZ
    0b111: 'PZ',
}

cnd_j4 = {
    0b1000: 'LE',
    0b1001: 'O',
    0b1010: 'GE',
    0b1100: 'GT',
    0b1101: 'NO',
    0b1110: 'LT',
}

cnd_bm4 = {
    0b0000: 'GEU', # C
    0b0001: 'GTU',
    0b0010: 'EQ', # Z
    0b0011: 'N',
    0b0100: 'LE',
    0b0101: 'O',
    0b0110: 'GE',
    0b1000: 'LTU', # NC
    0b1001: 'LEU',
    0b1010: 'NE', # NZ
    0b1011: 'PZ',
    0b1100: 'GT',
    0b1101: 'NO',
    0b1110: 'LT',
}

cnd_bm8 = {
    0b0000_0000: 'GEU', # C
    0b0000_0001: 'GTU',
    0b0000_0010: 'EQ', # Z
    0b0000_0011: 'N',
    0b0000_0100: 'LE',
    0b0000_0101: 'O',
    0b0000_0110: 'GE',
    0b1111_1000: 'LTU', # NC
    0b1111_1001: 'LEU',
    0b1111_1010: 'NE', # NZ
    0b1111_1011: 'PZ',
    0b1111_1100: 'GT',
    0b1111_1101: 'NO',
    0b1111_1110: 'LT',
}

llil_cond = {
    # Comparisons
    'EQ':  LowLevelILFlagCondition.LLFC_E,
    'NE':  LowLevelILFlagCondition.LLFC_NE,
    'PZ':  LowLevelILFlagCondition.LLFC_POS,
    'N':   LowLevelILFlagCondition.LLFC_NEG,
    'GE':  LowLevelILFlagCondition.LLFC_SGE,
    'GT':  LowLevelILFlagCondition.LLFC_SGT,
    'LT':  LowLevelILFlagCondition.LLFC_SLT,
    'LE':  LowLevelILFlagCondition.LLFC_SLE,
    'GEU': LowLevelILFlagCondition.LLFC_UGE,
    'LTU': LowLevelILFlagCondition.LLFC_ULT,
    'GTU': LowLevelILFlagCondition.LLFC_UGT,
    'LEU': LowLevelILFlagCondition.LLFC_ULE,
    # Flags
    'C':   LowLevelILFlagCondition.LLFC_ULT, # LLFC_C,
    'NC':  LowLevelILFlagCondition.LLFC_UGE, # LLFC_NC,
    'Z':   LowLevelILFlagCondition.LLFC_E,   # LLFC_Z,
    'NZ':  LowLevelILFlagCondition.LLFC_NE,  # LLFC_NZ,
    'O':   LowLevelILFlagCondition.LLFC_O,
    'NO':  LowLevelILFlagCondition.LLFC_NO,
}
