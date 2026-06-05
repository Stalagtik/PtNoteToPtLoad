# PT_NOTE to PT_LOAD ELF Injector

This project demonstrates how to modify an ELF binary on Linux (x86_64) to inject a custom shellcode. It accomplishes this by converting a `PT_NOTE` segment header into a loadable `PT_LOAD` segment header, redirecting the entry point, and appending the shellcode to the end of the binary.

Developed by **TheoOrigin** as part of the 3SI4 school curriculum.

---

## How it Works

The assembler program (`cc1.s`) executes the following steps:
1. **File I/O**: Opens the target ELF file (`cc1c`) in read/write mode.
2. **Size Resolution**: Measures the size of the target ELF.
3. **Parse Program Headers**: Searches through the ELF program header table to locate a `PT_NOTE` segment.
4. **Segment Modification**:
   - Converts the segment type to `PT_LOAD` (`p_type` = `1`).
   - Marks the segment permissions as Read/Execute (`p_flags` = `5`).
   - Assigns a virtual memory address at a safe offset (usually aligned relative to the file size).
   - Adjusts the file and memory size fields of the segment header to accommodate the shellcode.
   - Sets the segment offset to point to the end of the file.
5. **Entry Point Redirection**: Overwrites the ELF header's entry point (`e_entry`) to jump directly to the newly defined virtual address where the shellcode is placed.
6. **Append Shellcode**: Writes the payload shellcode at the very end of the file.

---

## Assembly & Build Instructions

Compile and run the assembly injector using `nasm` and `ld` (Linux environment):

```bash
# Assemble and link the injector, then run it on target cc1c
nasm -f elf64 -o cc1.o cc1.s && ld -o cc1 cc1.o && ./cc1 cc1c
```

---

## Verification

### 1. View ELF Program Headers
Run `readelf` to observe that the `PT_NOTE` segment has been successfully converted to `PT_LOAD`:
```bash
readelf -Wl cc1c
```
Verify the following updates in the modified segment:
- Type becomes `LOAD` instead of `NOTE`.
- Virtual address (`VirtAddr`), offset, alignment, file size, memory size, and flags (`R E`) are modified.
- The ELF entry point (`Entry point`) matches the new shellcode virtual address.

### 2. File Inspection
Using a hex editor like `ghex`, you can inspect the modified `cc1c` binary to verify that the shellcode payload has been successfully appended to the end of the file.
