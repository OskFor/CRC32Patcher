namespace CRC32Patcher.Helper
{
    internal class Memory
    {
        static ProcessMemory Reader;

        static Memory()
        {
            Reader = new ProcessMemory("process");
        }

        public static ProcessMemory ProcessMemory
        {
            get { return Reader; }
        }

        public static T Read<T>(IntPtr address) where T : struct
        {
            return Reader.Read<T>(address);
        }

        public static byte[] ReadBytes(IntPtr address, int amount)
        {
            return Reader.Read(address, amount);
        }

        public static void Write<T>(IntPtr address, T val) where T : struct
        {
            Reader.Write<T>(address, val);
        }

        public static void WriteString(IntPtr address, string val)
        {
            Reader.WriteCString(address, val);
        }

        public static void WriteBytes(IntPtr address, byte[] val)
        {
            Reader.Write(address, val);
        }

        public static string ReadString(IntPtr address, int maxLen)
        {
            return Reader.ReadCString(address, maxLen);
        }

        public static IntPtr BaseAddress
        {
            get { return Reader.BaseAddress; }
        }
        public static string ModuleName
        {
            get { return Reader.ModuleName; }
        }
        public static string FileVersionInfo
        {
            get { return Reader.FileVersionInfo.ToString(); }
        }
    }
}
