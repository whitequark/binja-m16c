import json
import struct

from binaryninja import Architecture, Platform, BinaryView
from binaryninja.enums import SegmentFlag, SectionSemantics
from binaryninja.settings import Settings


__all__ = ['RenesasM16CRawBinaryView']


Settings().register_setting('arch.m16c.ramSize', json.dumps({
    "title": "M16C RAM Size",
    "description": "Specify the amount of address space allocated for internal RAM.",
    "type": "number",
    "minValue": 0,
    "maxValue": 31,
    "default": 31,
}))


class RenesasM16CRawBinaryView(BinaryView):
    name = "M16C ROM"
    long_name = "M16C ROM Binary"

    @classmethod
    def is_valid_for_data(cls, data):
        # Because the first instruction after reset *must* be `LDC #IMM16, ISP`, we can detect
        # raw M16C ROM dumps pretty reliably:
        #  * ROM size may not exceed 512K
        if not (0 < len(data) <= 0x80000):
            return False
        #  * ROM size must be a multiple of page size
        if len(data) % 0x100 != 0:
            return False
        #  * reset vector must point into the ROM
        reset_vector, = struct.unpack("<L", data.read(len(data) - 4, 4))
        if not (0 < 0x100000 - (reset_vector & 0xFFFFF) < len(data)):
            return False
        #  * first instruction must be `LDC #IMM16, ISP`
        if data.read(len(data) - (0x100000 - (reset_vector & 0xFFFFF)), 2) != b"\xEB\x40":
            return False
        # Probably an M16C ROM then!
        return True

    def __init__(self, data):
        BinaryView.__init__(self, data.file, data)

        self.arch = Architecture['m16c']
        self.platform = Platform['m16c']

    def init(self):
        data = self.parent_view

        ram_size = Settings().get_integer('arch.m16c.ramSize') * 1024

        seg_rw_  = (SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentWritable)
        seg_r_x  = (SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentExecutable)
        seg_code = SegmentFlag.SegmentContainsCode
        seg_data = SegmentFlag.SegmentContainsData
        self.add_auto_segment(0x400, ram_size,
                              0, 0,
                              seg_rw_|seg_data)
        self.add_auto_segment(0x100000 - len(data), len(data),
                              data.start, len(data),
                              seg_r_x|seg_code|seg_data)

        sec_default = SectionSemantics.DefaultSectionSemantics
        sec_ro_code = SectionSemantics.ReadOnlyCodeSectionSemantics
        sec_ro_data = SectionSemantics.ReadOnlyDataSectionSemantics
        sec_rw_data = SectionSemantics.ReadWriteDataSectionSemantics
        self.add_auto_section('.sfr',    0, 0x400,
                              sec_default)
        self.add_auto_section('.data',   0x400, ram_size,
                              sec_rw_data)
        self.add_auto_section('.text',   0x100000 - len(data), len(data),
                              sec_ro_code)
        self.add_auto_section('.rodata', 0x100000 - len(data), len(data),
                              sec_ro_data)

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        reset_vector, = struct.unpack("<L", self.read(0xFFFFC, 4))
        return reset_vector & 0xFFFFF


RenesasM16CRawBinaryView.register()
