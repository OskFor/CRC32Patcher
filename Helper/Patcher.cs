using System.Diagnostics;
using System.Runtime.InteropServices;
using static CRC32Patcher.Helper.ProcessMemory;

namespace CRC32Patcher.Helper
{
    internal class Patcher
    {
        public static bool Run()
        {
            System.Diagnostics.Process.Start(new ProcessStartInfo("C:/game.exe"));

            // Wait for process to be loaded before continuing, dumb way to check for window title to be loaded but seems reliable
            while (System.Diagnostics.Process.GetProcessesByName("process")[0].MainWindowTitle == "") { Thread.Sleep(100); }
            IntPtr procHandle = OpenProcess(ProcessAccessFlags.PROCESS_ALL_ACCESS, false, Memory.ProcessMemory.Process.Id);

            if (procHandle == IntPtr.Zero)
                return false;

            // Wait for D3D module to be loaded, could perhaps be anything in .pdata as well, but this seems to work
            Console.WriteLine("Waiting for d3d11.dll module to be loaded");
            int count = 0;
            while (count < 1000) // Timeout if it's taking too long
            {
                if (Memory.ProcessMemory.Process.Modules.Cast<ProcessModule>().Any(m => m.ModuleName == "d3d11.dll"))
                {
                    break;
                }

                Thread.Sleep(5);
                count++;
            }

            Console.WriteLine("Executable: " + Memory.ModuleName);
            Console.WriteLine("BaseAddress: " + Memory.BaseAddress.ToString("X"));

            // Suspending process is necessary to complete the remapping of memory
            NtSuspendProcess(procHandle);

            int bytes = VirtualQueryEx(procHandle, Memory.BaseAddress, out MEMORY_BASIC_INFORMATION bi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
            if (bytes == 0)
                return false;

            IntPtr biBase = bi.baseAddress;
            IntPtr biRegionSize = bi.regionSize;

            Console.WriteLine("Performing memory remapping");
            // Implementation idea for memory remapping from https://github.com/Evulpes/Remap-Memory-Region
            IntPtr addr = MemoryRemap(procHandle, biBase, biRegionSize.ToInt32(), MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);

            // At this point memory should be remapped, and we can clean up by resuming the process and closing the handle
            NtResumeProcess(procHandle);
            CloseHandle(procHandle);
            Console.WriteLine("Done with memory remapping");
            return true;
        }


        public static IntPtr MemoryRemap(IntPtr processHandle, IntPtr baseAddress, int regionSize, MemoryProtectionConstraints constraints)
        {
            IntPtr address = VirtualAllocEx(processHandle, IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, constraints);
            if (address == IntPtr.Zero)
                return IntPtr.Zero;

            IntPtr buffer = VirtualAlloc(IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, constraints);
            IntPtr bufferEx = VirtualAllocEx(processHandle, IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            byte[] buffer2 = new byte[regionSize];

            if (!ReadProcessMemory(processHandle, baseAddress, buffer, regionSize, out IntPtr bytes))
                return IntPtr.Zero;

            if (!ReadProcessMemory(processHandle, baseAddress, buffer2, regionSize, out bytes))
                return IntPtr.Zero;

            IntPtr hSection = IntPtr.Zero;
            long maxSize = regionSize;
            
            Ntstatus status = NtCreateSection(ref hSection, AccessMask.SECTION_ALL_ACCESS, IntPtr.Zero, ref maxSize, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE, SectionProtectionConstraints.SEC_COMMIT, IntPtr.Zero);
            
            if (status != Ntstatus.STATUS_SUCCESS)
                return IntPtr.Zero;

            status = NtUnmapViewOfSection(processHandle, baseAddress);

            if (status != Ntstatus.STATUS_SUCCESS)
                return IntPtr.Zero;
            
            long sectionOffset = default;
            uint viewSize = 0;
            
            status = NtMapViewOfSection(hSection, processHandle, ref baseAddress, UIntPtr.Zero, regionSize, ref sectionOffset, ref viewSize, 2, 0, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);

            if (status != Ntstatus.STATUS_SUCCESS)
                return IntPtr.Zero;
            
            
            if (!WriteProcessMemory(processHandle, baseAddress, buffer, (int)viewSize, out bytes))
                return IntPtr.Zero;

            if (!WriteProcessMemory(processHandle, bufferEx, buffer, (int)viewSize, out bytes))
                return IntPtr.Zero;


            // If we wanted to insert hooks, we could do it at this point


            // The example process has CRC32 integrity checks
            // The full list of different CRC32 instructions are
            // F2 0F 38 F0
            // F2 ?? 0F 38 F0
            // F2 0F 38 F1
            // F2 0F 38 F1
            // F2 ?? 0F 38 F0
            // F2 ?? 0F 38 F1
            // The example process only had CRC32 instructions of type F2 ?? 0F 38 F1, but others could be easily added here
            // We search for this pattern from the entire memory region, and patch them as we find them
            byte[] crcPattern = { 0xF2, 0x00, 0x0F, 0x38, 0xF1 };
            for (long i = 0; i < regionSize; i++)
            {
                bool crcFound = false;
                for (long j = 0; j < crcPattern.Length; j++)
                {
                    // Since the second byte is a wildcard in the CRC32 check, we don't care about the value of buffer2[i+j] when crcPattern[j] == 0x00
                    if (crcPattern[j] == 0x00 || buffer2[i + j] == crcPattern[j])
                    {
                        crcFound = true;
                    }
                    else
                    {
                        crcFound = false;
                        break;
                    }
                }
                if (crcFound)
                {
                    patchCRC(processHandle, (long)baseAddress + i, (long)baseAddress, (long)bufferEx);
                }
            }

            status = NtUnmapViewOfSection(processHandle, baseAddress);

            if (status != Ntstatus.STATUS_SUCCESS)
                return IntPtr.Zero;

            status = NtMapViewOfSection(hSection, processHandle, ref baseAddress, UIntPtr.Zero, regionSize, ref sectionOffset, ref viewSize, 2, 0, MemoryProtectionConstraints.PAGE_EXECUTE_READ);

            if (status != Ntstatus.STATUS_SUCCESS)
                return IntPtr.Zero;

            if (!VirtualFree(buffer, 0, MemFree.MEM_RELEASE))
                return IntPtr.Zero;

            return address;
        }



        public static bool patchCRC(IntPtr processHandle, long crcAddress, long imgBase, long imgCopyBase)
        {
            // The idea of this method is to redirect the CRC32 check to be performed on the "clean" memory section (imgCopyBase)
            // To do this we first overwrite the original CRC32 check with a detour that jumps into our code cave
            // The CRC32 check defines which region of memory it scans through.
            // In our code cave we want to subtract the base address of imgBase, and add the base address of imgCopyBase to the section being scanned
            // We can then perform the original CRC32 check, which should now succeed
            // After this we return to where our code cave was called from, and fix our register and stack


            // Save value of rax
            // Place the address of our codecave to rax
            // Call rax
            // Pop the original value of rax
            byte[] detour =
            {
                0x50,                                                               // push rax
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov rax, CaveAddr (0x03)
                0xFF, 0xD0,                                                         // call rax
                0x58                                                                // pop rax
            };

            byte[] codeCave =
            {
                // Change the scan address (in rdi) to be from our "clean" memory section (imgCopyBase)
                0x51,                                                               // push rcx
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov rcx, imgBase (0x03)
                0x48, 0x29, 0xCF,                                                   // sub rdi, rcx
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov rcx, imgCopyBase (0x10)
                0x48, 0x01, 0xCF,                                                   // add rdi, rcx
                0x59,                                                               // pop rcx
                // Bytes that will be replaced by the original CRC32 check
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                // Return to where our code cave was called from
                0xC3
            };

            IntPtr caveAddr = VirtualAllocEx(processHandle, IntPtr.Zero, codeCave.Length, MemoryAllocationType.MEM_COMMIT, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            if (caveAddr == IntPtr.Zero)
                return false;

            // Get the bytes corresponding addresses of our codeCave and imgBases
            // Insert the cave address bytes to detour
            // Insert the img base address bytes to codeCave
            // Insert the img base copy address (the original memory section that passes the check) bytes to codeCave
            Array.Copy(BitConverter.GetBytes(caveAddr.ToInt64()), 0, detour, 0x03, 8);
            Array.Copy(BitConverter.GetBytes(imgBase), 0, codeCave, 0x03, 8);
            Array.Copy(BitConverter.GetBytes(imgCopyBase), 0, codeCave, 0x10, 8);

            // We want to copy the original CRC32 instruction to our code cave to be executed after we have swapped the address of the memory region to be scanned
            // Read the original CRC32 check instructions to crcCheck
            byte[] crcCheck = new byte[88];
            if (!ReadProcessMemory(processHandle, (IntPtr)crcAddress, crcCheck, crcCheck.Length, out IntPtr bytes))
                return false;


            // The last instruction of the CRC32 check should be jb (0x72)
            // Find 0x72 from the original CRC32 check instructions
            // Get the length of the full CRC32 check as well, so that we know how long it is to overwrite it later with our detour
            // The section for the original CRC32 instructions starts at 0x1C in the code cave
            // With this info, we can copy the original CRC32 instruction into the correct spot in the code cave
            int crcCheckLength = Array.IndexOf(crcCheck, 0x72) + 2;
            Array.Copy(crcCheck, 0, codeCave, 0x1C, crcCheckLength + 1);


            // TODO:
            //
            // 1.
            // Dynamically adjust the register used in our detour in case rax is used in our code cave
            // To implement we would have to go through the original CRC32 check (in crcCheck) and see which registers it uses
            // After that we can adjust the OPcodes in our detour accordingly to an unused register
            //
            // 2.
            // Dynamically adjust the registers in our codeCave to match the ones the original check uses
            // If the target process had more frequent CRC32 checks, they would most likely have varying registers that they use for the INC and CMP instructions
            // To implement we would have to go through the original CRC32 check (in crcCheck) and check the OPcodes that correspond to the registers in question
            // After that we can copy the corresponding OPcodes from crcCheck to our codeCave to the correct locations



            // Since we perform the CRC32 check in our code cave, we want to completely overwrite the original CRC32 check.
            // We still need to (potentially) add more NOP (0x90) instructions to the end of our detour to make it cleanly replace the whole original CRC32 instruction
            // Otherwise we risk returning to an invalid OPcode
            byte[] detourFixedLength = detour.Concat(Enumerable.Repeat((byte)0x90, crcCheckLength - detour.Length)).ToArray();

            // Finally we can write our detour and code cave
            if (!WriteProcessMemory(processHandle, (IntPtr)(crcAddress), detourFixedLength, detourFixedLength.Length, out bytes))
                return false;

            if (!WriteProcessMemory(processHandle, caveAddr, codeCave, codeCave.Length, out bytes))
                return false;

            return true;
        }
    }
}
