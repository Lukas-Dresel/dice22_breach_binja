from binaryninja import Architecture, CallingConvention


__all__ = ['DefaultCallingConvention',]


class BreachCallingConvention(CallingConvention):
    caller_saved_regs = ['R0', 'R1']
    caller_saved_regs = ['R6', 'R7']
    int_arg_regs = ['R8', 'R9', 'R10', 'R11', 'R12', 'R13']
    int_return_reg = 'R8'


arch = Architecture['Breach']
arch.register_calling_convention(BreachCallingConvention(arch, 'default'))