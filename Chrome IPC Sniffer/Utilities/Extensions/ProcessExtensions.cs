using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;

namespace ChromiumIPCSniffer
{
    public static class ProcessExtensions
    {
        public static bool useWMI = false;
        public static string GetCommandLine(this Process process)
        {
            if (useWMI)
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + process.Id))
                using (ManagementObjectCollection objects = searcher.Get())
                {
                    return objects.Cast<ManagementBaseObject>().SingleOrDefault()?["CommandLine"]?.ToString();
                }
            }
            else
            {
                // max size of a command line is USHORT / sizeof(WCHAR), so we are going
                // just allocate max USHORT for sanity's sake.
                var sb = new StringBuilder(0xFFFF);
                switch (IntPtr.Size)
                {
                    case 8: GetProcCmdLine64((uint)process.Id, sb, (uint)sb.Capacity); break;
                }
                return sb.ToString();
            }
        }

        public static IntPtr GetModuleBaseAddress(this Process process, string moduleName)
        {

            foreach (ProcessModule module in process.Modules)
            {
                if (string.Equals(module.ModuleName, moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    return module.BaseAddress;
                }
            }

            return IntPtr.Zero; // Not found
        }

        public static bool WriteMemory(this Process p, IntPtr address, byte[] data)
        {
            var hProc = OpenProcess(ProcessAccessRights.PROCESS_VM_WRITE | ProcessAccessRights.PROCESS_VM_READ | ProcessAccessRights.PROCESS_VM_OPERATION, false, (int)p.Id);

            MemPageProtect oldProtect;
            bool success = VirtualProtectEx(hProc.DangerousGetHandle(), address, data.Length, MemPageProtect.PAGE_EXECUTE_READWRITE, out oldProtect);
            if (!success)
            {
                Console.WriteLine("[-] VirtualProtectEx failed on PID " + p.Id + ", error: " + Marshal.GetLastWin32Error());
                return false;
            }

            int wtf = 0;
            success = WriteProcessMemory(hProc.DangerousGetHandle(), address, data, data.Length, out wtf);
            if (!success)
            {
                Console.WriteLine("[-] WriteProcessMemory failed on PID " + p.Id + ". error: " + Marshal.GetLastWin32Error());
                return false;
            }

            MemPageProtect oldProtect2;
            success = VirtualProtectEx(hProc.DangerousGetHandle(), address, data.Length, oldProtect, out oldProtect2);
            if (!success)
            {
                Console.WriteLine("[-] VirtualProtectEx (second call) failed on PID " + p.Id + ". error: " + Marshal.GetLastWin32Error());
                return false;
            }

            CloseHandle(hProc.DangerousGetHandle());

            return true;
        }


        public static byte[] ReadMemory(this Process p, IntPtr address, long size)
        {
            SafeProcessHandle hProc = OpenProcess(ProcessAccessRights.PROCESS_VM_READ, false, (int)p.Id);
            if (hProc.IsInvalid)
            {
                Console.WriteLine("[-] Could not OpenProcess on PID " + p.Id + ", Error: " + Marshal.GetLastWin32Error());
                return null;
            }

            byte[] dataRead = new byte[size];
            int wtf = 0;
            bool success = ReadProcessMemory(hProc.DangerousGetHandle(), address, dataRead, dataRead.Length, out wtf);
            if (!success)
            {
                Console.WriteLine("[-] ReadProcessMemory failed on PID " + p.Id + ", Error: " + Marshal.GetLastWin32Error());
                return null;
            }
            

            CloseHandle(hProc.DangerousGetHandle());

            return dataRead;
        }


        [DllImport("ProcCmdLine64.dll", CharSet = CharSet.Unicode, EntryPoint = "GetProcCmdLine")]
        public extern static bool GetProcCmdLine64(uint nProcId, StringBuilder sb, uint dwSizeBuf);

        #region ENUMs
        internal enum NT_STATUS
        {
            STATUS_SUCCESS = 0x00000000,
            STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005L),
            STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004L)
        }

        [Flags]
        internal enum ProcessAccessRights
        {
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_ALL_ACCESS = 0x1FFFFF,

            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_READWRITE = 0x04,
        }


        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [Flags]
        private enum PROCESS_ACCESS_FLAGS : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000
        }

        public enum MemPageState : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_FREE = 0x10000,
        }

        public enum MemPageType : uint
        {
            MEM_PRIVATE = 0x20000,
            MEM_MAPPED = 0x40000,
            MEM_IMAGE = 0x1000000
        }

        [Flags]
        public enum MemPageProtect : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
        }
        

        #endregion

        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        internal sealed class SafeObjectHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeObjectHandle()
                : base(true)
            { }

            internal SafeObjectHandle(IntPtr preexistingHandle, bool ownsHandle)
                : base(ownsHandle)
            {
                base.SetHandle(preexistingHandle);
            }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(base.handle);
            }
        }

        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        internal sealed class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeProcessHandle()
                : base(true)
            { }

            internal SafeProcessHandle(IntPtr preexistingHandle, bool ownsHandle)
                : base(ownsHandle)
            {
                base.SetHandle(preexistingHandle);
            }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(base.handle);
            }
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess([In] ProcessAccessRights dwDesiredAccess, [In, MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, [In] int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, MemPageProtect flNewProtect, out MemPageProtect lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int GetProcessId(
            [In] IntPtr Process);


        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int QueryDosDevice(
            [In] string lpDeviceName,
            [Out] StringBuilder lpTargetPath,
            [In] int ucchMax);

        [DllImport("ntdll.dll")]
        private static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(PROCESS_ACCESS_FLAGS dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);


        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);


        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll")]
        static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

        private const int MAX_PATH = 260;
        private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        private const int DUPLICATE_SAME_ACCESS = 0x2;
        private const uint FILE_SEQUENTIAL_ONLY = 0x00000004;
        private const int CNST_SYSTEM_HANDLE_INFORMATION = 0x10;
        private const int CNST_SYSTEM_HANDLE_INFORMATION_EX = 64;
        private static int OBJECT_TYPE_FILE = -1;
    }
}
