import re

from .instr import Instruction


encodings = {
    # '0111_011z_1111_dddd': Abs,

    # '0111_011z_0110_dddd': AdcImm,
    # '1011_000z_ssss_dddd': AdcReg,
    # '0111_011z_1110_dddd': Adcf,

    # '0111_011z_0100_dddd': AddImm,
    # '1100_100z_iiii_dddd': AddImm4,
    # '1000_0ddd': AddImm8,
    # '1010_000z_ssss_dddd': AddReg,
    # '0010_0dss': AddReg8,
    # '0111_110z_1110_1011': AddImmSP,
    # '0111_1101_1011_iiii': AddImm4SP,

    # '1111_100z_iiii_dddd': Adjnz,

    # '0111_011z_0010_dddd': AndImm,
    # '1001_0ddd': AndImm8,
    # '1001_000z_ssss_dddd': AndReg,
    # '0001_0dss': AndReg8,

    # '0111_1110_0100_ssss': Band,
    # '0111_1110_1000_dddd': Bclr,
    # '0100_0bbb': BclrSB,
    # '0111_1110_0010_dddd': Bmcnd,
    # '0111_1101_1101_cccc': BmcndC,
    # '0111_1110_0101_ssss': Bnand,
    # '0111_1110_0111_ssss': Bnor,
    # '0111_1110_1010_dddd': Bnot,
    # '0101_0bbb': BnotSB,
    # '0111_1110_0011_ssss': Bntst,
    # '0111_1110_1101_ssss': Bnxor,
    # '0111_1110_0110_ssss': Bor,
    # '0000_0000': Brk,
    # '0111_1110_1001_dddd': Bset,
    # '0100_1bbb': BsetSB,
    # '0111_1110_1011_dddd': Btst,
    # '0101_1bbb': BtstSB,
    # '0111_1110_0000_dddd': Btstc,
    # '0111_1110_0001_dddd': Btsts,
    # '0111_1110_1100_ssss': Bnxor,

    # '0111_011z_1000_dddd': CmpImm,
    # '1101_000z_iiii_dddd': CmpImm4,
    # '1110_0ddd': CmpImm8,
    # '1100_000z_ssss_dddd': CmpReg,
    # '0011_1dss': CmpReg8,

    # '0111_1100_1110_1110': DadcImm8,
    # '0111_1101_1110_1110': DadcImm16,
    # '0111_1100_1110_0110': DadcReg8,
    # '0111_1101_1110_0110': DadcReg16,

    # '0111_1100_1110_1100': DaddImm8,
    # '0111_1101_1110_1100': DaddImm16,
    # '0111_1100_1110_0100': DaddReg8,
    # '0111_1101_1110_0100': DaddReg16,

    # '1010_1ddd': Dec8,
    # '1111_d010': DecAdr,

    # '0111_110z_1110_0001': DivImm,
    # '0111_011z_1101_ssss': DivReg,
    # '0111_110z_1110_0000': DivuImm,
    # '0111_011z_1100_ssss': DivuReg,
    # '0111_110z_1110_0011': DivxImm,
    # '0111_011z_1001_ssss': DivxReg,

    # '0111_1100_1110_1111': DsbbImm8,
    # '0111_1101_1110_1111': DsbbImm16,
    # '0111_1100_1110_0111': DsbbReg8,
    # '0111_1101_1110_0111': DsbbReg16,

    # '0111_1100_1110_1101': DsubImm8,
    # '0111_1101_1110_1101': DsubImm16,
    # '0111_1100_1110_0101': DsubReg8,
    # '0111_1101_1110_0101': DsubReg16,

    # '0111_1100_1111_0010': Enter,
    # '0111_1101_1111_0010': Exitd,

    # '0111_1100_0110_dddd': Exts,
    # '0111_1100_1111_0011': ExtsR0,

    # '1110_1011_0xxx_0101': Fclr,
    # '1110_1011_0xxx_0100': Fset,

    # '1010_0ddd': Inc8,
    # '1011_d010': IncAdr,

    # '1110_1011': Int,
    # '1111_0110': Into,

    # '0110_1ccc': Jcnd1,
    # '0111_1101_1100_cccc': Jcnd2,

    # '0110_0ppp': Jmp3,
    # '1111_1110': Jmp8,
    # '1111_0100': Jmp16,
    # '1111_1100': JmpAbs,
    # '0111_1101_0010_ssss': Jmpi,
    # '0111_1101_0000_ssss': JmpiAbs,
    # '1110_1110': Jmps,

    # '1111_0101': Jsr,
    # '1111_1101': JsrAbs,
    # '0111_1101_0011_ssss': Jsri,
    # '0111_1101_0001_ssss': JsriAbs,
    # '1110_1111': Jsrs,

    # '1110_1011_0ddd_0000': LdcImm16,
    # '0111_1010_1ddd_ssss': LdcReg,

    # '0111_1100_1111_0000': Ldctx,

    # '0111_010z_1000_dddd': Lde,
    # '0111_010z_1001_dddd': LdeA0,
    # '0111_010z_1010_dddd': LdeA1A0,

    # '0111_1101_1010_0iii': Ldipl,

    # '0111_010z_1100_dddd': MovImm,
    # '1101_100z_iiii_dddd': MovImm4,
    # '1100_0ddd': MovImm8,
    # '1z10_d010': MovImmAdr,
    # '1011_0ddd': MovZeroReg8,
    # '0111_001z_ssss_dddd': MovReg,
    # '0011_0dss': MovRegAdr,
    # '0000_0sdd': MovReg8Reg,
    # '0000_1dss': MovRegReg8,
    # '0111_010z_1011_dddd': MovIndSPReg,
    # '0111_010z_0011_ssss': MovRegIndSP,
    # '1110_1011_0ddd_ssss': Mova,
    # '0111_1100_10rr_dddd': MovdirR0LReg,
    # '0111_1100_00rr_ssss': MovdirRegR0L,

    # '0111_110z_0101_dddd': MulImm,
    # '0111_100z_ssss_dddd': MulReg,
    # '0111_110z_0100_dddd': MuluImm,
    # '0111_000z_ssss_dddd': MuluReg,

    # '0111_010z_0101_dddd': Neg,

    # '0000_0100': Nop,

    # '0111_010z_0111_dddd': Not,
    # '1011_1ddd': NotReg8,

    # '0111_011z_0011_dddd': OrImm,
    # '1001_1ddd': OrImm8,
    # '1001_100z_ssss_dddd': OrReg,
    # '0001_1dss': OrReg8,

    # '0111_010z_1101_dddd': Pop,
    # '1001_d010': PopReg8,
    # '1101_d010': PopAdr,
    # '1110_1011_0ddd_0011': Popc,
    # '1110_1101': Popm,

    # '0111_110z_1110_0010': PushImm,
    # '0111_010z_0100_ssss': Push,
    # '1000_s010': PushReg8,
    # '1100_s010': PushAdr,
    # '0111_1101_1001_ssss': Pusha,
    # '1110_1011_0sss_0010': Pushc,
    # '1110_1100': Pushm,

    # '1111_1011': Reit,

    # '0111_110z_1111_0001': Rmpa,

    # '0111_011z_1010_dddd': Rolc,
    # '0111_011z_1011_dddd': Rorc,
    # '1110_000z_iiii_dddd': Rot,
    # '0111_010z_0110_dddd': RotR1H,

    # '1111_0011': Rts,

    # '0111_011z_0111_dddd': SbbImm,
    # '1011_100z_ssss_dddd': SbbReg,

    # '1111_000z_iiii_dddd': ShaImm4,
    # '0111_010z_1111_dddd': ShaR1H,
    # '1110_1011_101d_iiii': Sha32Imm4,
    # '1110_1011_001d_0001': Sha32R1H,

    # '1110_000z_iiii_dddd': ShlImm4,
    # '0111_010z_1110_dddd': ShlR1H,
    # '1110_1011_100d_iiii': Shl32Imm4,
    # '1110_1011_000d_0001': Shl32R1H,

    # '0111_110z_1110_1001': Smovb,
    # '0111_110z_1110_1000': Smovf,
    # '0111_110z_1110_1010': Sstr,

    # '0111_1011_1sss_dddd': Stc,
    # '0111_1100_1100_dddd': StcPc,

    # '0111_1101_1111_0000': Stctx,

    # '0111_010z_0000_ssss': Ste,
    # '0111_010z_0001_ssss': SteA0,
    # '0111_010z_0010_ssss': SteA1A0,

    # '1101_0ddd': Stnz,
    # '1100_1ddd': Stz,
    # '1101_1ddd': Stzx,

    # '0111_011z_0101_dddd': SubImm,
    # '1000_1ddd': SubImm8,
    # '1010_100z_ssss_dddd': SubReg,
    # '0010_1dss': SubReg8,

    # '0111_011z_0000_dddd': TstImm,
    # '1000_000z_ssss_dddd': TstReg,

    # '1111_1111': Und,

    # '0111_1101_1111_0011': Wait,

    # '0111_101z_00ss_dddd': Xchg,

    # '0111_011z_0001_dddd': XorImm,
    # '1000_100z_ssss_dddd': XorReg,
}


def generate_tables():
    for encoding, instr in encodings.items():
        def expand_encoding(table, parts):
            part, *parts = parts
            assert len(part) == 4

            chunks = []
            try:
                chunks.append(int(part, 2))
            except ValueError:
                instr_code   = int(re.sub(r"[^01]", "0", part), 2)
                instr_mask   = int(re.sub(r"[^01]", "0", part.replace("0", "1")), 2)
                operand_mask = int(re.sub(r"[^01]", "1", part.replace("1", "0")), 2)
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

            for chunk in chunks:
                if parts:
                    try:
                        subtable = table[chunk]
                    except KeyError:
                        subtable = table[chunk] = dict()
                    assert isinstance(subtable, dict)
                    expand_encoding(subtable, parts)
                else:
                    assert chunk not in table
                    table[chunk] = instr

        parts = encoding.split('_')
        while not re.search(r"[01]", parts[-1]):
            parts.pop()
        expand_encoding(Instruction.opcodes, parts)

generate_tables()
