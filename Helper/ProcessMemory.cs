using System.Globalization;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace CRC32Patcher.Helper
{
    public class ProcessMemory : IDisposable
    {
        private System.Diagnostics.Process process;


        public IntPtr BaseAddress
        {
            get { return process.MainModule.BaseAddress; }
        }

        public String ModuleName
        {
            get { return process.MainModule.ModuleName; }
        }

        public System.Diagnostics.FileVersionInfo FileVersionInfo
        {
            get { return process.MainModule.FileVersionInfo; }
        }

        public System.Diagnostics.Process Process
        {
            get { return process; }
        }

        public ProcessMemory(System.Diagnostics.Process process)
        {
            OpenProcess(process);
        }

        public ProcessMemory(int pid)
        {
            OpenProcess(System.Diagnostics.Process.GetProcessById(pid));
        }

        public ProcessMemory(string processName)
        {
            OpenProcess(GetProcessByName(processName));
        }

        private void OpenProcess(System.Diagnostics.Process _process)
        {
            process = _process;
        }

        ~ProcessMemory()
        {
            process.Close();
            process.Dispose();
        }

        private static System.Diagnostics.Process GetProcessByName(string processName)
        {
            var p = System.Diagnostics.Process.GetProcessesByName(processName);

            if (p.Length == 0)
                throw new Exception(String.Format(CultureInfo.InvariantCulture, "{0} isn't running!", processName));

            return p[0];
        }

        public byte[] Read(IntPtr offset, int length)
        {
            var result = new byte[length];
            ReadProcessMemory(process.Handle, offset, result, new IntPtr(length), IntPtr.Zero);
            return result;
        }

        public bool Write(IntPtr offset, byte[] data)
        {
            return WriteProcessMemory(process.Handle, offset, data, new IntPtr(data.Length), IntPtr.Zero);
        }

        public string ReadCString(IntPtr offset, int maxLen)
        {
            return Encoding.UTF8.GetString(Read(offset, maxLen).TakeWhile(ret => ret != 0).ToArray());
        }

        public bool WriteCString(IntPtr offset, string str)
        {
            return Write(offset, Encoding.UTF8.GetBytes(str + '\0'));
        }

        public T Read<T>(IntPtr offset) where T : struct
        {
            byte[] result = new byte[Marshal.SizeOf(typeof(T))];
            ReadProcessMemory(process.Handle, offset, result, new IntPtr(result.Length), IntPtr.Zero);
            GCHandle handle = GCHandle.Alloc(result, GCHandleType.Pinned);
            T returnObject = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return returnObject;
        }

        public T Read<T>(IntPtr baseAddr, params int[] offsets) where T : struct
        {
            IntPtr ptr = Read<IntPtr>(baseAddr);

            if (ptr != IntPtr.Zero)
            {
                for (int i = 0; i < offsets.Length; ++i)
                {
                    if (i == offsets.Length - 1)
                        return Read<T>(ptr + offsets[i]);

                    ptr = Read<IntPtr>(ptr + offsets[i]);
                }
            }

            return default(T);
        }

        public void Write<T>(IntPtr offset, T value) where T : struct
        {
            byte[] buffer = new byte[Marshal.SizeOf(value)];
            IntPtr hObj = Marshal.AllocHGlobal(buffer.Length);
            try
            {
                Marshal.StructureToPtr(value, hObj, false);
                Marshal.Copy(hObj, buffer, 0, buffer.Length);
                Write(offset, buffer);
            }
            finally
            {
                Marshal.FreeHGlobal(hObj);
            }
        }

        public void Dispose()
        {
            process.Close();
            process.Dispose();
        }

        [DllImport("kernel32.dll", SetLastError = true), SuppressUnmanagedCodeSecurity]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr nSize, IntPtr lpNumberOfBytesRead);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int size, out IntPtr lpNumberOfBytesRead);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int size, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true), SuppressUnmanagedCodeSecurity]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, IntPtr lpNumberOfBytesWritten);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("Kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll")]
        public static extern void NtSuspendProcess(IntPtr processHandle);

        [DllImport("ntdll.dll")]
        public static extern void NtResumeProcess(IntPtr processHandle);

        [DllImport("ntdll.dll")]
        public static extern Ntstatus NtCreateSection(ref IntPtr sectionHandle, AccessMask DesiredAccess, IntPtr objectAttributes, ref long MaximumSize, MemoryProtectionConstraints SectionPageProtection, SectionProtectionConstraints AllocationAttributes, IntPtr fileHandle);

        [DllImport("ntdll.dll")]
        public static extern Ntstatus NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, UIntPtr ZeroBits, int commitSize, ref long SectionOffset, ref uint ViewSize, uint InheritDisposition, MemoryAllocationType allocationType, MemoryProtectionConstraints win32Protect);

        [DllImport("ntdll.dll")]
        public static extern Ntstatus NtUnmapViewOfSection(IntPtr processHandle, IntPtr baseAddress);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr handle, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, MemoryAllocationType flAllocationType, MemoryProtectionConstraints flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, MemoryAllocationType flAllocationType, MemoryProtectionConstraints flProtect);
        
        [DllImport("Kernel32.dll")]
        public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, MemFree dwFreeType);


        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr baseAddress;
            public IntPtr allocationBase;
            public MemoryProtectionConstraints allocationProtect;
            public IntPtr regionSize;
            public State state;
            public MemoryProtectionConstraints protect;
            public Type type;
        }

        public enum ProcessAccessFlags
        {
            PROCESS_ALL_ACCESS = 0xFFFF,
        }

        public enum Ntstatus : uint
        {
            STATUS_ACCESS_VIOLATION = 3221225477,
            STATUS_SUCCESS = 0,
            STATUS_FILE_LOCK_CONFLICT = 0xC0000054,
            STATUS_INVALID_FILE_FOR_SECTION = 0xC0000020,
            STATUS_INVALID_PAGE_PROTECTION = 0xC0000045,
            STATUS_MAPPED_FILE_SIZE_ZERO = 0xC000011E,
            STATUS_SECTION_TOO_BIG = 0xC0000040,
        }

        public enum AccessMask : uint
        {
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            SECTION_QUERY = 0x0001,
            SECTION_MAP_WRITE = 0x0002,
            SECTION_MAP_READ = 0x0004,
            SECTION_MAP_EXECUTE = 0x0008,
            SECTION_EXTEND_SIZE = 0x0010,
            SECTION_MAP_EXECUTE_EXPLICIT = 0x0020,
            SECTION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE)
        }

        public enum SectionProtectionConstraints
        {
            SEC_COMMIT = 0x08000000,
        }

        public enum MemoryAllocationType
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000
        }

        public enum MemoryProtectionConstraints : uint
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
        }

        public enum MemFree
        {
            MEM_RELEASE = 0x00008000,
        }

        public enum State
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000,
        }
    }
}
