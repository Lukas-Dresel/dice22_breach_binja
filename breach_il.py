#!/usr/bin/env python
#
# separate module for lifting, two main exports:
# gen_flag_il()
# gen_instr_il()

# Binja includes
from tempfile import tempdir
from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.enums import LowLevelILOperation, LowLevelILFlagCondition
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILLabel, ILRegister, ILFlag, LLIL_TEMP, LLIL_GET_TEMP_REG_INDEX

from breach_dis import DecodedInstruction, Opcode, OperandType, Register, ALU_Opcode, decode
from . import consts


REG_TO_SIZE = {
    f'R{i}': 8 for i in range(16)
}
#------------------------------------------------------------------------------
# LOOKUP TABLES
#------------------------------------------------------------------------------

def goto_or_jump(target_type, target_val, il):
    if target_type == OperandType.IMM64_PROGRAM_ADDRESS:
        addr = consts.VM_CODE_START + target_val
        tmp = il.get_label_for_address(Architecture['Breach'], addr)
        if tmp:
            return il.goto(tmp)
        else:
            return il.jump(il.const_pointer(8, addr))
    else:
        assert target_type == OperandType.REG_PROGRAM_ADDRESS
        return il.jump(il.add(8, il.const_pointer(8, consts.VM_CODE_START), il.reg(8, target_val.name)))

def append_conditional_instr(cond, instr, il):
    t = LowLevelILLabel()
    f = LowLevelILLabel()
    il.append(il.if_expr(cond, t, f))
    il.mark_label(t)
    il.append(instr)
    il.mark_label(f)

def append_conditional_jump(reg1, reg2, target_type, target_val, addr_fallthru, il):
    # case: condition and label available
    assert target_type == OperandType.IMM64_PROGRAM_ADDRESS
    target_addr = consts.VM_CODE_START + target_val
    cond = il.compare_equal(1, reg1, reg2)
    t = il.get_label_for_address(Architecture['Breach'], target_addr)
    f = il.get_label_for_address(Architecture['Breach'], addr_fallthru)
    if t and f:
        il.append(il.if_expr(cond, t, f))
        return

    # case: conditional and address available
    tmp = goto_or_jump(target_type, target_val, il)
    append_conditional_instr(cond, tmp, il)

def operand_to_il(oper_type, oper_val, il):
    if oper_type in {OperandType.REG, OperandType.REG_SYSCALL_NUM}:
        return il.reg(8, oper_val.name)
    elif oper_type == OperandType.REG_GLOBAL_ADDRESS:
        return il.add(8, il.const_pointer(8, consts.VM_DATA_START), il.reg(8, oper_val.name))
    elif oper_type == OperandType.REG_PROGRAM_ADDRESS:
        return il.add(8, il.const_pointer(8, consts.VM_CODE_START), il.reg(8, oper_val.name))

    elif oper_type == OperandType.IMM64:
        return il.const(8, oper_val)

    elif oper_type == OperandType.IMM64_PROGRAM_ADDRESS:
        return il.const_pointer(8, consts.VM_CODE_START + oper_val)

    elif oper_type == OperandType.ALU_OP:
        assert False

    else:
        raise Exception("unknown operand type: " + str(oper_type))

#------------------------------------------------------------------------------
# INSTRUCTION LIFTING
#------------------------------------------------------------------------------

def gen_instr_il(addr, decoded: DecodedInstruction, il):
    if decoded.opcode == Opcode.HALT:
        il.append(il.system_call())

    elif decoded.opcode == Opcode.LOAD_REG_IMM:
        il.append(il.set_reg(8,
                    decoded.operands[0][1].name,
                    operand_to_il(*decoded.operands[1], il),
        ))

    elif decoded.opcode in {Opcode.LOAD64_PROGRAM, Opcode.LOAD64_GLOBAL}:
        il.append(il.set_reg(
            8,
            decoded.operands[0][1].name,
            il.load(8, operand_to_il(*decoded.operands[1], il))
        ))

    elif decoded.opcode in {Opcode.MOV_REG_REG}:
        il.append(il.set_reg(
                8,
                decoded.operands[0][1].name,
                operand_to_il(*decoded.operands[1], il),
            )
        )

    elif decoded.opcode in {Opcode.STORE64_GLOBAL}:
        il.append(il.store(
                8,
                operand_to_il(*decoded.operands[0], il),
                operand_to_il(*decoded.operands[1], il),
            )
        )

    elif decoded.opcode in {Opcode.ALU_OP}:
        v1, v2 = operand_to_il(*decoded.operands[1], il), operand_to_il(*decoded.operands[2], il)
        OPERATION = {
            ALU_Opcode.ADD: il.add,
            ALU_Opcode.AND: il.and_expr,
            ALU_Opcode.MOD: il.mod_unsigned,
            ALU_Opcode.MUL: il.mult,
            ALU_Opcode.OR: il.or_expr,
            ALU_Opcode.RSHIFT: il.logical_shift_right,
            ALU_Opcode.SUB: il.sub,
            ALU_Opcode.XOR: il.xor_expr,
        }[decoded.operands[0][1]]
        il.append(il.set_reg(
                8,
                decoded.operands[1][1].name,
                OPERATION(8, v1, v2),
            )
        )

    elif decoded.opcode in {Opcode.JMP_ABSOLUTE, Opcode.JMP_REG}:
        il.append(goto_or_jump(*decoded.operands[0], il))

    elif decoded.opcode in {Opcode.JMP_EQ}:
        append_conditional_jump(
            operand_to_il(*decoded.operands[0], il),
            operand_to_il(*decoded.operands[1], il),
            *decoded.operands[2],
            addr + 10,
            il
            )

    elif decoded.opcode in {Opcode.META_VM_CALL}:
        il.append(il.call(operand_to_il(*decoded.operands[0], il)))

    elif decoded.opcode in {Opcode.META_VM_RET}:
        il.append(il.set_reg(
            8,
            'STACKP',
            il.add(8, il.reg(8,'STACKP'), il.const(8, 8))
        ))
        il.append(il.ret(
            il.load(8, il.sub(8, il.reg(8, 'STACKP'), il.const(8, 8)))
        ))

    elif decoded.opcode in {Opcode.META_VM_RET}:
        il.append(il.set_reg(
            8,
            'STACKP',
            il.add(8, il.reg(8,'STACKP'), il.const(8, 8))
        ))
        il.append(il.ret(
            il.load(8, il.sub(8, il.reg(8, 'STACKP'), il.const(8, 8)))
        ))

    elif decoded.opcode in {Opcode.META_VM_PUSH_REG}:
        il.append(il.push(8, operand_to_il(*decoded.operands[0], il)))

    elif decoded.opcode in {Opcode.META_VM_POP}:
        il.append(il.set_reg(8, decoded.operands[0][1].name, il.pop(8)))

    elif decoded.opcode in {Opcode.STACK_OP}:
        il.append(il.unimplemented())

    else:
        print(f"unimplemented opcode lifter: {decoded} @ {hex(addr)}")
        il.append(il.unimplemented())
        #il.append(il.nop()) # these get optimized away during lifted il -> llil

    if addr == 0x50014ca:
        il.append(il.no_ret())

