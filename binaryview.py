import struct

from binaryninja import Architecture, Platform, BinaryView
from binaryninja.enums import SegmentFlag, SectionSemantics


__all__ = ['RenesasM16CRawBinaryView']


class RenesasM16CRawBinaryView(BinaryView):
    name = "M16C ROM"
    long_name = "Raw M16C ROM"

    @classmethod
    def is_valid_for_data(cls, data):
        # No especially good way to detect raw M16C ROM dumps, so let's use a few heuristics:
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
        # Could be an M16C ROM then.
        return True

    def __init__(self, data):
        BinaryView.__init__(self, data.file, data)

        self.arch = Architecture['m16c']
        self.platform = Platform['m16c']

    def init(self):
        data = self.parent_view

        seg_rw_  = (SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentWritable)
        seg_r_x  = (SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentExecutable)
        seg_code = SegmentFlag.SegmentContainsCode
        seg_data = SegmentFlag.SegmentContainsData
        self.add_auto_segment(0x400, 0x8000 - 0x400,
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
        self.add_auto_section('.bss',    0x400, 0x8000 - 0x400,
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
