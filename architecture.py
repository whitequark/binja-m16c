import json
from binaryninja import log, Architecture, RegisterInfo, IntrinsicInfo, InstructionInfo
from binaryninja.enums import Endianness, FlagRole, LowLevelILFlagCondition
from binaryninja.types import Type
from binaryninja.settings import Settings

from . import mc


__all__ = ['RenesasM16CArchitecture']


Settings().register_setting('arch.m16c.showSuffix', json.dumps({
    "title": "M16C Disassembly Suffix",
    "description": "Whether or not to display the :G/:Q/:S/:Z suffix.",
    "type": "boolean",
    "default": True,
}))


class RenesasM16CArchitecture(Architecture):
    name = "m16c"
    endianness = Endianness.LittleEndian

    default_int_size = 2
    address_size = 3

    stack_pointer = 'SP'
    regs = {
        # Data (banked in hardware)
        'R2R0': RegisterInfo('R2R0', 4, 0),
            'R0': RegisterInfo('R2R0', 2, 0),
                'R0L': RegisterInfo('R0L', 1, 0),
                'R0H': RegisterInfo('R0H', 1, 1),
            'R2': RegisterInfo('R2R0', 2, 2),
        'R3R1': RegisterInfo('R3R1', 4, 0),
            'R1': RegisterInfo('R3R1', 2, 0),
                'R1L': RegisterInfo('R1L', 1, 0),
                'R1H': RegisterInfo('R1H', 1, 1),
            'R3': RegisterInfo('R3R1', 2, 2),
        # Address
        'A1A0': RegisterInfo('A1A0', 4, 0),
            'A0': RegisterInfo('A1A0', 2, 0),
            'A1': RegisterInfo('A1A0', 2, 2),
        # Frame base (banked in hardware)
        'FB': RegisterInfo('FB', 2, 0),
        # Program counter
        'PC': RegisterInfo('PC', 2, 0),
        # Stack pointer (banked in hardware as USP/ISP)
        'SP': RegisterInfo('SP', 2, 0),
        # Static base
        'SB': RegisterInfo('SB', 2, 0),
    }
    flags = [
        'C', # Carry
        'D', # Debug
        'Z', # Zero
        'S', # Sign
        'B', # Register bank select
        'O', # Overflow
        'I', # Interrupt enable
        'U', # Stack pointer select
        # IPL is not modelled
    ]
    flag_roles = {
        'C': FlagRole.CarryFlagRole,
        'D': FlagRole.SpecialFlagRole,
        'Z': FlagRole.ZeroFlagRole,
        'S': FlagRole.NegativeSignFlagRole,
        'B': FlagRole.SpecialFlagRole,
        'O': FlagRole.OverflowFlagRole,
        'I': FlagRole.SpecialFlagRole,
        'U': FlagRole.SpecialFlagRole,
    }

    def get_instruction_info(self, data, addr):
        decoded = mc.decode(data, addr)
        if decoded:
            info = InstructionInfo()
            decoded.analyze(info, addr)
            return info

    def get_instruction_text(self, data, addr):
        decoded = mc.decode(data, addr)
        if decoded:
            encoded = data[:decoded.length()]
            recoded = mc.encode(decoded, addr)
            if encoded != recoded:
                log.log_error("Instruction roundtrip error")
                log.log_error("".join([str(x) for x in decoded.render(addr)]))
                log.log_error("Orig: {}".format(encoded.hex()))
                log.log_error("New:  {}".format(recoded.hex()))

            decoded.show_suffix = Settings().get_bool('arch.m16c.showSuffix')
            return decoded.render(addr), decoded.length()

    def get_instruction_low_level_il(self, data, addr, il):
        decoded = mc.decode(data, addr)
        if decoded:
            decoded.lift(il, addr)
            return decoded.length()


RenesasM16CArchitecture.register()
