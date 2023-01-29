namespace CRC32Patcher.Helper
{
    class CRC32Patcher
    {
        static void Main(string[] args)
        {
            Helper.Patcher.Run();
            Console.WriteLine("Finished memory remap+crc patcher");
        }
    }
}