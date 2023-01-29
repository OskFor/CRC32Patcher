# CRC32Patcher

Implementation for memory remapping from https://github.com/Evulpes/Remap-Memory-Region

Some games have implemented CRC32 checks, which generate a checksum from a memory section to see if the code has been tampered with. One idea for working around these checks is to:
1. Map a copy of the game's memory and change the page protection to [PAGE_EXECUTE_READWRITE](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants) (copy 1)
2. Map a copy of the game's memory to keep as a "clean" section. This section should remain unedited so that it can be used to spoof the CRC32 checks (copy 2)
3. Patch all of the CRC32 calls in copy 1
    1. The idea is to perform the CRC32 on the "clean" copied memory section (copy 2)
    2. Original CRC32 check is overwritten with a detour to our code (in copy 1 since we now have write access)
    3. The detour adjusts the register containing the scan region, by subtracting the base address of the original process, and adding the base address of the copied process
    4. The detour then performs the original CRC32 check, which succeeds on the clean section
    5. The detour finally returns back to where it was called from
4. Unmap the memory at the base address of the process
5. Map copy 1 back to the base address of the process

The end result of this should be that we have the the memory region starting at the base address with writing rights and patched CRC32 calls, and another untampered copy of the memory that is used to perform said CRC32 calls.
