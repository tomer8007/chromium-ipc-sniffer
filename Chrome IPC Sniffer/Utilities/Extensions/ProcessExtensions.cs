using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ChromeIPCSniffer
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

        [DllImport("ProcCmdLine64.dll", CharSet = CharSet.Unicode, EntryPoint = "GetProcCmdLine")]
        public extern static bool GetProcCmdLine64(uint nProcId, StringBuilder sb, uint dwSizeBuf);
    }
}
