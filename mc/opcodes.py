import re

from . import tables
from .instr import Instruction
from .instr.nop import *
from .instr.alu import *
from .instr.bcd import *
from .instr.bit import *
from .instr.flag import *
from .instr.mov import *
from .instr.smov import *
from .instr.ld_st import *
from .instr.stack import *
from .instr.jmp import *
from .instr.call import *
from .instr.ctx import *
from .instr.trap import *


enumerations = {
    'R': tables.rx_ax,
    'I': tables.dsp8_dsp16_abs16,
    '6': tables.dsp8_abs16,
    '7': tables.r0x_r0y_dsp8_abs16,
    '8': tables.r0x_dsp8_abs16,
    'A': tables.reg16_dsp8_dsp16_dsp20_abs16,
    'E': tables.reg8l_dsp8_dsp16_abs16,
    'N': tables.reg8_dsp8_dsp16_abs16,
    'C': tables.creg,
    'J': tables.cnd_j3,
    'K': tables.cnd_j4,
    'M': tables.cnd_bm4,
}


encodings = {
    '0111_011z_1111_dddd': AbsReg,

    '0111_011z_0110_dddd': AdcImm,
    '1011_000z_ssss_dddd': AdcReg,
    '0111_011z_1110_dddd': Adcf,

    '0111_011z_0100_dddd': AddImm,
    '1100_100z_iiii_dddd': AddImm4,
    '1000_0DDD;8': AddImm8,
    '1010_000z_ssss_dddd': AddReg,
    '0010_0DSS;7': AddReg8,
    '0111_110z_1110_1011': AddImmSP,
    '0111_1101_1011_iiii': AddImm4SP,

    '1111_100z_iiii_dddd': Adjnz,

    '0111_011z_0010_dddd': AndImm,
    '1001_0DDD;8': AndImm8,
    '1001_000z_ssss_dddd': AndReg,
    '0001_0DSS;7': AndReg8,

    '0111_1110_0100_ssss': Band,
    '0111_1110_1000_dddd': Bclr,
    '0100_0bbb': BclrSB,
    '0111_1110_0010_dddd': Bmcnd,
    '0111_1101_1101_CCCC;M': BmcndC,
    '0111_1110_0101_ssss': Bnand,
    '0111_1110_0111_ssss': Bnor,
    '0111_1110_1010_dddd': Bnot,
    '0101_0bbb': BnotSB,
    '0111_1110_0011_ssss': Bntst,
    '0111_1110_1101_ssss': Bnxor,
    '0111_1110_0110_ssss': Bor,
    '0111_1110_1001_dddd': Bset,
    '0100_1bbb': BsetSB,
    '0111_1110_1011_ssss': Btst,
    '0101_1bbb': BtstSB,
    '0111_1110_0000_dddd': Btstc,
    '0111_1110_0001_dddd': Btsts,
    '0111_1110_1100_ssss': Bxor,

    '0000_0000': Brk,

    '0111_011z_1000_dddd': CmpImm,
    '1101_000z_iiii_dddd': CmpImm4,
    '1110_0DDD;8': CmpImm8,
    '1100_000z_ssss_dddd': CmpReg,
    '0011_1DSS;7': CmpReg8,

    '0111_1100_1110_1110': DadcImm8,
    '0111_1101_1110_1110': DadcImm16,
    '0111_1100_1110_0110': DadcReg8,
    '0111_1101_1110_0110': DadcReg16,

    '0111_1100_1110_1100': DaddImm8,
    '0111_1101_1110_1100': DaddImm16,
    '0111_1100_1110_0100': DaddReg8,
    '0111_1101_1110_0100': DaddReg16,

    '1010_1DDD;8': Dec,
    '1111_d010': DecAdr,

    '0111_110z_1110_0001': DivImm,
    '0111_011z_1101_ssss': DivReg,
    '0111_110z_1110_0000': DivuImm,
    '0111_011z_1100_ssss': DivuReg,
    '0111_110z_1110_0011': DivxImm,
    '0111_011z_1001_ssss': DivxReg,

    '0111_1100_1110_1111': DsbbImm8,
    '0111_1101_1110_1111': DsbbImm16,
    '0111_1100_1110_0111': DsbbReg8,
    '0111_1101_1110_0111': DsbbReg16,

    '0111_1100_1110_1101': DsubImm8,
    '0111_1101_1110_1101': DsubImm16,
    '0111_1100_1110_0101': DsubReg8,
    '0111_1101_1110_0101': DsubReg16,

    '0111_1100_1111_0010': Enter,
    '0111_1101_1111_0010': Exitd,

    '0111_1100_0110_DDDD;E': Exts,
    '0111_1100_1111_0011': ExtsR0,

    '1110_1011_0fff_0101': Fclr,
    '1110_1011_0fff_0100': Fset,

    '1010_0DDD;8': Inc,
    '1011_d010': IncAdr,

    '1110_1011_11ii_iiii': Int,
    '1111_0110': Into,

    '0110_1CCC;J': Jcnd1,
    '0111_1101_1100_CCCC;K': Jcnd2,

    '0110_0iii': Jmp3,
    '1111_1110': Jmp8,
    '1111_0100': Jmp16,
    '1111_1100': JmpAbs,
    '0111_1101_0010_ssss': Jmpi,
    '0111_1101_0000_SSSS;A': JmpiAbs,
    '1110_1110': Jmps,

    '1111_0101': Jsr16,
    '1111_1101': JsrAbs,
    '0111_1101_0011_ssss': Jsri,
    '0111_1101_0001_SSSS;A': JsriAbs,
    '1110_1111': Jsrs,

    '1110_1011_0DDD;C_0000': LdcImm,
    '0111_1010_1DDD;C_ssss': LdcReg,

    '0111_1100_1111_0000': Ldctx,

    '0111_010z_1000_dddd': Lde,
    '0111_010z_1001_dddd': LdeA0,
    '0111_010z_1010_dddd': LdeA1A0,

    '0111_1101_1010_0iii': Ldipl,

    '0111_010z_1100_dddd': MovImmReg,
    '1101_100z_iiii_dddd': MovImm4Reg,
    '1100_0DDD;8': MovImm8Reg,
    '1110_d010': MovImm8Adr,
    '1010_d010': MovImm16Adr,
    '1011_0DDD;8': MovZero8Reg,
    '0111_001z_ssss_dddd': MovRegReg,
    '0011_0dss': MovRegAdr,
    '0000_0sDD;6': MovReg8Reg,
    '0000_1DSS;7': MovRegReg8,
    '0111_010z_1011_dddd': MovIndSPReg,
    '0111_010z_0011_ssss': MovRegIndSP,
    '1110_1011_0DDD;R_SSSS;I': Mova,
    '0111_1100_10rr_DDDD;N': MovdirR0LReg,
    '0111_1100_00rr_SSSS;N': MovdirRegR0L,

    '0111_110z_0101_dddd': MulImm,
    '0111_100z_ssss_dddd': MulReg,
    '0111_110z_0100_dddd': MuluImm,
    '0111_000z_ssss_dddd': MuluReg,

    '0111_010z_0101_dddd': NegReg,

    '0000_0100': Nop,

    '0111_010z_0111_dddd': NotReg,
    '1011_1DDD;8': NotReg8,

    '0111_011z_0011_dddd': OrImm,
    '1001_1DDD;8': OrImm8,
    '1001_100z_ssss_dddd': OrReg,
    '0001_1DSS;7': OrReg8,

    '0111_010z_1101_dddd': Pop,
    '1001_d010': PopReg8,
    '1101_d010': PopAdr,
    '1110_1011_0DDD;C_0011': Popc,
    '1110_1101': Popm,

    '0111_110z_1110_0010': PushImm,
    '0111_010z_0100_ssss': Push,
    '1000_s010': PushReg8,
    '1100_s010': PushAdr,
    '0111_1101_1001_SSSS;I': Pusha,
    '1110_1011_0SSS;C_0010': Pushc,
    '1110_1100': Pushm,

    '1111_1011': Reit,

    '0111_110z_1111_0001': Rmpa,

    '1110_000z_iiii_dddd': RotImm4,
    '0111_010z_0110_dddd': RotR1H,
    '0111_011z_1010_dddd': Rolc,
    '0111_011z_1011_dddd': Rorc,

    '1111_0011': Rts,

    '0111_011z_0111_dddd': SbbImm,
    '1011_100z_ssss_dddd': SbbReg,

    '1111_000z_iiii_dddd': ShaImm4,
    '0111_010z_1111_dddd': ShaR1H,
    '1110_1011_101d_iiii': Sha32Imm4,
    '1110_1011_001d_0001': Sha32R1H,

    '1110_100z_iiii_dddd': ShlImm4,
    '0111_010z_1110_dddd': ShlR1H,
    '1110_1011_100d_iiii': Shl32Imm4,
    '1110_1011_000d_0001': Shl32R1H,

    '0111_110z_1110_1001': Smovb,
    '0111_110z_1110_1000': Smovf,
    '0111_110z_1110_1010': Sstr,

    '0111_1011_1SSS;C_dddd': StcReg,
    '0111_1100_1100_DDDD;A': StcPc,

    '0111_1101_1111_0000': Stctx,

    '0111_010z_0000_ssss': Ste,
    '0111_010z_0001_ssss': SteA0,
    '0111_010z_0010_ssss': SteA1A0,

    '1101_0DDD;8': Stnz,
    '1100_1DDD;8': Stz,
    '1101_1DDD;8': Stzx,

    '0111_011z_0101_dddd': SubImm,
    '1000_1DDD;8': SubImm8,
    '1010_100z_ssss_dddd': SubReg,
    '0010_1DSS;7': SubReg8,

    '0111_011z_0000_dddd': TstImm,
    '1000_000z_ssss_dddd': TstReg,

    '1111_1111': Und,

    '0111_1101_1111_0011': Wait,

    '0111_101z_00ss_dddd': Xchg,

    '0111_011z_0001_dddd': XorImm,
    '1000_100z_ssss_dddd': XorReg,
}


def generate_tables():
    for encoding, instr in encodings.items():
        def expand_encoding(table, parts):
            part, *parts = parts
            if ';' in part:
                part, enum = part.split(';', 2)
            else:
                enum = ''
            assert len(part) == 4 and len(enum) <= 1

            chunks = []
            try:
                chunks.append(int(part, 2))
            except ValueError:
                wildcard_part = re.sub(r'[A-Z]', '0', part)
                instr_code   = int(re.sub(r'[^01]', '0', wildcard_part), 2)
                instr_mask   = int(re.sub(r'[^01]', '0', wildcard_part.replace('0', '1')), 2)
                operand_mask = int(re.sub(r'[^01]', '1', wildcard_part.replace('1', '0')), 2)
                operand_code = 0
                while True:
                    chunks.append(instr_code | operand_code)
                    if operand_code == operand_mask:
                        break
                    # The following line cleverly uses carries to make a counter only from the bits
                    # that are set in `operand_mask`. To understand it, consider that `instr_mask`
                    # is the inverse of `operand_mask`, and adding 1 to a 011...1 chunk changes it
                    # into a 100...0 chunk.
                    operand_code = ((operand_code | instr_mask) + 1) & operand_mask

                if enum:
                    shift = 4 - re.search(r'[A-Z]+', part).end()
                    chunks, chunk_templates = [], chunks
                    for template in chunk_templates:
                        for legal_bits in enumerations[enum]:
                            chunks.append(template | (legal_bits << shift))

            for chunk in chunks:
                if parts:
                    try:
                        subtable = table[chunk]
                    except KeyError:
                        subtable = table[chunk] = dict()
                    assert isinstance(subtable, dict)
                    expand_encoding(subtable, parts)
                else:
                    assert chunk not in table, "{} conflicts with {}".format(instr, table[chunk])
                    table[chunk] = instr

        parts = encoding.split('_')
        while re.match(r"^[a-z]+$", parts[-1]):
            parts.pop()
        expand_encoding(Instruction.opcodes, parts)


def print_assigned():
    def contract_encoding(table, parts):
        for part, entry in table.items():
            if isinstance(entry, dict):
                contract_encoding(entry, (*parts, part))
            else:
                encoding = '_'.join('{:04b}'.format(part) for part in (*parts, part))
                mnemonic = entry().name()
                print('{:20s} {}'.format(encoding, mnemonic))

    contract_encoding(Instruction.opcodes, ())


def print_unassigned():
    def contract_encoding(table, parts):
        unassigned = set(range(16))
        for part, entry in table.items():
            unassigned.remove(part)
            if isinstance(entry, dict):
                contract_encoding(entry, (*parts, part))
        for part in unassigned:
            print('_'.join('{:04b}'.format(part) for part in (*parts, part)))

    contract_encoding(Instruction.opcodes, ())


generate_tables()
# print_assigned()
# print_unassigned()
