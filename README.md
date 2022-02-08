# dice22_breach_binja
A Binary Ninja plugin for the VM of the DiceCTF 2022 `Breach` and `Containment` challenges


# Example

The main function after decompiles to something immensely readable and we can clearly see the logic of the program represented. This is accomplished by some instruction matching + meta opcode creation in the disassembly library [dice22_breach_dis](https://github.com/Lukas-Dresel/dice22_breach_dis/). With those meta opcodes binaryninja can infer methods, etc. correctly, and the control flow cleans up quite nicely.

![image](https://user-images.githubusercontent.com/13377119/153095141-c2d4e94c-95f6-406b-8427-b53b9989ac3a.png)


```C
int64_t main(int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6)

    int64_t binary_base
    int64_t R10_9
    binary_base, R10_9 = start_everything_by_nuking_libc_start_main_ret()
    syscall(SYS_pipe, binary_base + 0x6060, R10_9, arg4, arg5, arg6)
    int64_t R9_3 = binary_base + 0x6068
    syscall(SYS_pipe, R9_3, R10_9, arg4, arg5, arg6)
    if (syscall(SYS_fork, R9_3, R10_9, arg4, arg5, arg6) != 0)
        close_fd_pointed_to_by(0x200c, close_fd_pointed_to_by(0x2000, R9_3, R10_9, arg4, arg5, arg6), R10_9, arg4, arg5, arg6)
        int64_t R12
        int64_t R13
        R12, R13 = setup_seccomp(binary_base: binary_base)
        ram[0x2010].q = zx.q((ram[0x2004].q).d)
        ram[0x2018].q = zx.q((ram[0x2008].q).d)
        ram[0x2020].q = read_u64_from_host(0x140e0 + binary_base)
        int64_t bytes_read
        while (true)
            print_string(binary_base: binary_base, start: 0x2bf6, end: 0x2bfc)
            // print("Flag: ")
            // read(0, ROM_BASE, 0x60)
            bytes_read = syscall(SYS_read, 0, ram[0x2020].q, 0x60, R12, R13)
            if (bytes_read == 1)
                break
            ram[0x2028].q = bytes_read
            syscall(SYS_write, ram[0x2010].q, binary_base + 0x6088, 8)
            syscall(SYS_write, ram[0x2010].q, ram[0x2020].q, ram[0x2028].q)
            print_string(binary_base: binary_base, start: 0x2bfc, end: 0x2c08)  // print("Checking!")
            syscall(SYS_read, ram[0x2018].q, ram[0x2020].q, 1, R12, R13)
            if (zx.q(read_u64_from_host(ram[0x2020].q)) == 1)
                bytes_read = print_string(binary_base: binary_base, start: 0x2c0f, end: 0x2c18)  // print("Correct.")
                break
            print_string(binary_base: binary_base, start: 0x2c08, end: 0x2c0f)  // print("Wrong!")
        return bytes_read
    close_fd_pointed_to_by(0x2008, close_fd_pointed_to_by(0x2004, R9_3, R10_9, arg4, arg5, arg6), R10_9, arg4, arg5, arg6)
    close(0)
    int64_t R9_6 = close(1)
    ram[0x2010].q = zx.q((ram[0x200c].q).d)
    ram[0x2018].q = zx.q((ram[0x2000].q).d)
    int64_t R8_2
    int64_t R10
    int64_t R11
    R8_2, R10, R11 = read_u64_from_host(0x140e0 + binary_base)
    ram[0x2020].q = R8_2
    patch_print_opcode(R8_2, R9_6, R10, R11, arg5, arg6, binary_base: binary_base)
    while (true)
        syscall(SYS_read, ram[0x2018].q, ram[0x2020].q, 8)
        syscall(SYS_read, ram[0x2018].q, ram[0x2020].q, read_u64_from_host(ram[0x2020].q))
        copy_qword(ram[0x2020].q, do_stackmachine_stuff())
        syscall(SYS_write, ram[0x2010].q, ram[0x2020].q, 1, arg5, arg6)

```
