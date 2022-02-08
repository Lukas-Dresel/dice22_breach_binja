import binascii
import struct
import traceback

from .breach_arch import BreachArch
from . import consts

from binaryninja import Type
from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.log import log_error, log_info
from binaryninja.types import Symbol

# straight up stolen from https://github.com/ZetaTwo/binja-gameboy
class BreachProgramView(BinaryView):
    name = 'Breach'
    long_name = 'BREACH Program'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture[BreachArch.name].standalone_platform
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        return data.read(0x2933, 8) == b'DiceGang'

    def data_sym(self, addr, name, _type):
        self.define_auto_symbol_and_var_or_function(
            Symbol(SymbolType.DataSymbol, addr, name),
            _type
        )
        self.set_comment_at(addr, "Symbol: " + name)

    def init(self):
        # Add ROM mappings
        # ROM0
        pre_heap_size = consts.VM_CODE_START - consts.HEAP_BASE
        self.add_auto_segment(consts.HEAP_BASE, consts.VM_CODE_START - consts.HEAP_BASE, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentWritable)
        self.add_auto_section(
            "heap",
            consts.HEAP_BASE,
            consts.VM_CODE_START + consts.VM_CODE_SIZE - consts.HEAP_BASE,
            SectionSemantics.ReadWriteDataSectionSemantics
        )
        self.define_auto_symbol_and_var_or_function(
            Symbol(SymbolType.DataSymbol, consts.HEAP_BASE, "heap_base"),
            Type.array(Type.int(1), pre_heap_size)
        )
        self.set_comment_at(consts.HEAP_BASE, "heap_base")



        self.add_auto_segment(consts.VM_CODE_START, consts.VM_CODE_SIZE, 0, consts.VM_CODE_SIZE, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

        self.add_auto_section("CODE", consts.VM_CODE_START, consts.VM_CODE_SIZE, SectionSemantics.ReadOnlyCodeSectionSemantics)
        # ROM1

        self.add_auto_segment(consts.VM_DATA_START - 0x60, consts.VM_DATA_SIZE + 0x60, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_auto_section("bss_start", consts.VM_DATA_START - 0x60, 0x60,
                              SectionSemantics.ReadWriteDataSectionSemantics)

        self.add_auto_section('ram', consts.VM_DATA_START, 0x3000, SectionSemantics.ReadWriteDataSectionSemantics)
        self.add_auto_section('stack_machine_stack', consts.VM_DATA_START+0x3000, 0x5000, SectionSemantics.ReadWriteDataSectionSemantics)
        self.add_auto_section('decoded_rop_chain', consts.VM_DATA_START+0x8000, 0x1000, SectionSemantics.ReadWriteDataSectionSemantics)
        self.add_auto_section('vm_stack', consts.VM_DATA_START+0x9000, 0x7000, SectionSemantics.ReadWriteDataSectionSemantics)
        self.add_auto_section('vm_meta', consts.VM_DATA_START+0x10000, 0x80, SectionSemantics.ReadWriteDataSectionSemantics)

        self.data_sym(consts.VM_DATA_START-0x60, "bss_start", Type.array(Type.int(1), 0))
        self.data_sym(consts.VM_DATA_START, "ram", Type.array(Type.int(1), 0x3000))
        self.data_sym(consts.VM_DATA_START+0x3000, "stack_machine_stack", Type.array(Type.int(1), 0x5000))
        self.data_sym(consts.VM_DATA_START+0x8000, "decoded_rop_chain", Type.array(Type.int(1), 0x8000))
        self.data_sym(consts.VM_DATA_START+0x10000, "vm_meta", Type.array(Type.int(1), 0x80))

        # Define entrypoint
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, consts.VM_CODE_START, "vm_code_start"))
        self.add_entry_point(consts.VM_CODE_START)

        return True

    def perform_is_valid_offset(self, addr):
        # valid ROM addresses are the upper-half of the address space
        if addr >= consts.VM_CODE_START and addr < consts.VM_CODE_START + consts.VM_CODE_SIZE:
            return True
        return False

    def perform_get_start(self):
        return consts.VM_CODE_START

    def perform_get_length(self):
        return consts.VM_CODE_SIZE

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return consts.VM_CODE_START