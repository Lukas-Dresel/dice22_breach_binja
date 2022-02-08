#!/usr/bin/env python

import re

from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType, FlagRole, LowLevelILFlagCondition

from breach_dis import Opcode, OperandType, decode
from . import breach_il
from . import consts

class BreachArch(Architecture):
    name = 'Breach'

    address_size = 8
    default_int_size = 8
    instr_alignment = 1
    max_instr_length = 0x100

    # register related stuff
    regs = {
        # main registers
        'R0': RegisterInfo('R0', 8),
        'R1': RegisterInfo('R1', 8),
        'R2': RegisterInfo('R2', 8),
        'R3': RegisterInfo('R3', 8),
        'R4': RegisterInfo('R4', 8),
        'R5': RegisterInfo('R5', 8),
        'R6': RegisterInfo('R6', 8),
        'R7': RegisterInfo('R7', 8),
        'R8': RegisterInfo('R8', 8),
        'R9': RegisterInfo('R9', 8),
        'R10': RegisterInfo('R10', 8),
        'R11': RegisterInfo('R11', 8),
        'R12': RegisterInfo('R12', 8),
        'R13': RegisterInfo('R13', 8),
        'R14': RegisterInfo('R14', 8),
        'STACKP': RegisterInfo('STACKP', 8),

        'SP': RegisterInfo('STACKP', 8),
        # program counter
        'PC': RegisterInfo('PC', 8),
    }

    stack_pointer = "SP"

#------------------------------------------------------------------------------
# FLAG fun
#------------------------------------------------------------------------------

    flags = ['z', 'h', 'n', 'c']

    # remember, class None is default/integer
    semantic_flag_classes = ['class_bitstuff']

    # flag write types and their mappings
    flag_write_types = ['dummy', 'z']
    flags_written_by_flag_write_type = {
        'dummy': [],
        'z': ['z'],
    }

    # roles
    flag_roles = {
        'z': FlagRole.ZeroFlagRole,
    }
#------------------------------------------------------------------------------
# CFG building
#------------------------------------------------------------------------------

    def get_instruction_info(self, data, addr):
        decoded = decode(data, addr)

        # on error, return nothing
        if not decoded.success():
            return None

        # on non-branching, return length
        result = InstructionInfo()
        result.length = decoded.length
        if decoded.opcode == Opcode.JMP_ABSOLUTE:
            result.add_branch(BranchType.UnconditionalBranch, decoded.operands[0][1] + consts.VM_CODE_START)
        elif decoded.opcode == Opcode.JMP_REG:
            result.add_branch(BranchType.IndirectBranch)
        elif decoded.opcode == Opcode.JMP_EQ:
            result.add_branch(BranchType.TrueBranch, decoded.operands[2][1] + consts.VM_CODE_START)
            result.add_branch(BranchType.FalseBranch, addr + decoded.length)
        # ret from interrupts
        elif decoded.opcode == Opcode.META_VM_RET:
            result.add_branch(BranchType.FunctionReturn)
        elif decoded.opcode == Opcode.META_VM_CALL:
            result.add_branch(BranchType.CallDestination, decoded.operands[0][1])

        return result

# from api/python/function.py:
#
#        TextToken                  Text that doesn't fit into the other tokens
#        InstructionToken           The instruction mnemonic
#        OperandSeparatorToken      The comma or whatever else separates tokens
#        RegisterToken              Registers
#        IntegerToken               Integers
#        PossibleAddressToken       Integers that are likely addresses
#        BeginMemoryOperandToken    The start of memory operand
#        EndMemoryOperandToken      The end of a memory operand
#        FloatingPointToken         Floating point number
    def get_instruction_text(self, data, addr):
        decoded = decode(data, addr)
        if not decoded.success():
            return None

        result = []

        # opcode
        result.append(InstructionTextToken( \
            InstructionTextTokenType.InstructionToken, decoded.opcode_name()))

        # space for operand
        if decoded.operands:
            result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))

        # operands
        for i, operand in enumerate(decoded.operands):
            (oper_type, oper_val) = operand

            if oper_type in {OperandType.REG, OperandType.STACK_REG}:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.RegisterToken, oper_val.name))

            elif oper_type == OperandType.REG_SYSCALL_NUM:
                toks = [
                    (InstructionTextTokenType.TextToken, 'syscall'),
                    (InstructionTextTokenType.BeginMemoryOperandToken, '['),
                    (InstructionTextTokenType.RegisterToken, oper_val.name),
                    (InstructionTextTokenType.EndMemoryOperandToken, ']'),
                ]
                result.extend([InstructionTextToken(*ts) for ts in toks])

            elif oper_type == OperandType.REG_GLOBAL_ADDRESS:
                toks = [
                    (InstructionTextTokenType.TextToken, 'data'),
                    (InstructionTextTokenType.BeginMemoryOperandToken, '['),
                    (InstructionTextTokenType.RegisterToken, oper_val.name),
                    (InstructionTextTokenType.EndMemoryOperandToken, ']'),
                ]
                result.extend([InstructionTextToken(*ts) for ts in toks])

            elif oper_type == OperandType.REG_PROGRAM_ADDRESS:
                toks = [
                    (InstructionTextTokenType.TextToken, 'code'),
                    (InstructionTextTokenType.BeginMemoryOperandToken, '['),
                    (InstructionTextTokenType.RegisterToken, oper_val.name),
                    (InstructionTextTokenType.EndMemoryOperandToken, ']'),
                ]
                result.extend([InstructionTextToken(*ts) for ts in toks])

            elif oper_type == OperandType.IMM64:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.PossibleAddressToken, hex(oper_val), oper_val))

            elif oper_type == OperandType.IMM64_PROGRAM_ADDRESS:
                toks = [
                    (InstructionTextTokenType.TextToken, 'code'),
                    (InstructionTextTokenType.BeginMemoryOperandToken, '['),
                    (InstructionTextTokenType.PossibleAddressToken, hex(oper_val), oper_val),
                    (InstructionTextTokenType.EndMemoryOperandToken, ']'),
                ]
                result.extend([InstructionTextToken(*ts) for ts in toks])

            elif oper_type in {OperandType.ALU_OP, OperandType.STACK_OP}:
                toks = [
                    (InstructionTextTokenType.TextToken, oper_val.name),
                ]

                result.extend([InstructionTextToken(*ts) for ts in toks])

            elif oper_type == OperandType.STACK_IMM8:
                result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(oper_val), oper_val))

            else:
                raise Exception('unknown operand type: ' + str(oper_type))

            # if this isn't the last operand, add comma
            if i < len(decoded.operands)-1:
                result.append(InstructionTextToken( \
                    InstructionTextTokenType.OperandSeparatorToken, ','))

        return result, decoded.length

#------------------------------------------------------------------------------
# LIFTING
#------------------------------------------------------------------------------

    # def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
    #     flag_il = LR35902IL.gen_flag_il(op, size, write_type, flag, operands, il)
    #     if flag_il:
    #         return flag_il

    #     return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)

    def get_instruction_low_level_il(self, data, addr, il):
        decoded = decode(data, addr)
        if not decoded.success():
            return None

        breach_il.gen_instr_il(addr, decoded, il)

        return decoded.length

        # LR35902IL.gen_instr_il(addr, decoded, il)

        # return decoded.len

    def convert_to_nop(data: bytes, addr: int = 0):
        return bytes([Opcode.NOP.value] * len(data))
