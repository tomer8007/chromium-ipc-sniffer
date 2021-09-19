using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;

namespace ChromiumIPCSniffer
{
    public class HandlesUtility
    {
        private static Dictionary<SYSTEM_HANDLE_INFORMATION_EX, string> filenamesCache = new Dictionary<SYSTEM_HANDLE_INFORMATION_EX, string>();
        private static SYSTEM_HANDLE_INFORMATION_EX[] handlesCache = null;
        private static Dictionary<string, List<uint>> involvedPIDsCache = new Dictionary<string, List<uint>>();

        public static IEnumerable<SYSTEM_HANDLE_INFORMATION_EX> GetAllHandles()
        {
            List<SYSTEM_HANDLE_INFORMATION_EX> handles = new List<SYSTEM_HANDLE_INFORMATION_EX>();
            int handlesInfoSize = Marshal.SizeOf(new SYSTEM_HANDLE_INFORMATION_EX()) * 20000;
            IntPtr ptrHandleData = IntPtr.Zero;
            try
            {
                ptrHandleData = Marshal.AllocHGlobal(handlesInfoSize);
                int length = 0;

                while (NtQuerySystemInformation(CNST_SYSTEM_HANDLE_INFORMATION_EX, ptrHandleData, handlesInfoSize, ref length) == STATUS_INFO_LENGTH_MISMATCH)
                {
                    handlesInfoSize = length;
                    Marshal.FreeHGlobal(ptrHandleData);
                    ptrHandleData = Marshal.AllocHGlobal(length);
                }

                long handleCount = Marshal.ReadIntPtr(ptrHandleData).ToInt64();
                IntPtr ptrHandleItem = ptrHandleData + Marshal.SizeOf(ptrHandleData) + Marshal.SizeOf(new IntPtr());

                for (long i = 0; i < handleCount; i++)
                {
                    SYSTEM_HANDLE_INFORMATION_EX oSystemHandleInfo = Marshal.PtrToStructure<SYSTEM_HANDLE_INFORMATION_EX>(ptrHandleItem);
                    ptrHandleItem += Marshal.SizeOf(new SYSTEM_HANDLE_INFORMATION_EX());

                    handles.Add(oSystemHandleInfo);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(ptrHandleData);
            }

            handlesCache = handles.ToArray();
            return handles;
        }

        public static IEnumerable<SYSTEM_HANDLE_INFORMATION_EX> GetHandlesForProcess(uint PID)
        {
            List<SYSTEM_HANDLE_INFORMATION_EX> processHandles = new List<SYSTEM_HANDLE_INFORMATION_EX>();
            foreach (SYSTEM_HANDLE_INFORMATION_EX handleInformation in GetAllHandles())
            {
                if ((int)handleInformation.ProcessID == PID)
                    processHandles.Add(handleInformation);
            }

            return processHandles;
        }

        public static List<string> GetProcessOpenFiles(uint pid)
        {
            List<string> openFiles = new List<string>();
            List<SYSTEM_HANDLE_INFORMATION_EX> handles = GetHandlesForProcess(pid).ToList();
            foreach (SYSTEM_HANDLE_INFORMATION_EX handleInfo in handles)
            {
                string filePath = GetFilenameOfRemoteHandle(handleInfo);
                if (!string.IsNullOrEmpty(filePath))
                {
                    openFiles.Add(filePath);
                }
            }
            return openFiles;
        }

        public static List<uint> GetProcessesUsingFile(string fileName, List<int> legalProcesses, bool useCache = true)
        {
            List<uint> involvedPIDs = new List<uint>();
            if (useCache)
            {
                //
                // First, look in the cache
                //

                if (involvedPIDsCache.ContainsKey(fileName)) return involvedPIDsCache[fileName];

                foreach (SYSTEM_HANDLE_INFORMATION_EX handleInformation in handlesCache)
                {
                    if (!IsOneOfProcesses((int)handleInformation.ProcessID, legalProcesses)) continue;

                    if (OBJECT_TYPE_FILE != -1 && handleInformation.ObjectType != OBJECT_TYPE_FILE) continue;

                    string name = GetFilenameOfRemoteHandle(handleInformation, useCache: useCache);
                    if (name == fileName)
                        involvedPIDs.Add((uint)handleInformation.ProcessID);
                }

                involvedPIDsCache[fileName] = involvedPIDs;

                if (involvedPIDs.Count >= 2)
                {
                    return involvedPIDs;
                }
            }

            //
            // Look in the real handles
            //
            foreach (SYSTEM_HANDLE_INFORMATION_EX handleInformation in GetAllHandles())
            {
                if (!IsOneOfProcesses((int)handleInformation.ProcessID, legalProcesses)) continue;

                if (OBJECT_TYPE_FILE != -1 && handleInformation.ObjectType != OBJECT_TYPE_FILE) continue;

                string name = GetFilenameOfRemoteHandle(handleInformation, useCache: useCache);
                if (name == fileName)
                    involvedPIDs.Add((uint)handleInformation.ProcessID);
            }

            involvedPIDsCache[fileName] = involvedPIDs;

            return involvedPIDs;
        }

        public static string GetFilePathFromFileObject(IntPtr fileObjectPointer, bool useCache = true)
        {
            string fileName = null;
            if (useCache)
            {
                //
                // First, look in the cache
                //
                foreach (SYSTEM_HANDLE_INFORMATION_EX handleInformation in handlesCache)
                {
                    if (handleInformation.ObjectPointer == fileObjectPointer)
                    {
                        fileName = GetFilenameOfRemoteHandle(handleInformation);
                        break;
                    }
                }

                if (fileName != null) return fileName;
            }

            //
            // Look in the real handles
            //
            foreach (SYSTEM_HANDLE_INFORMATION_EX handleInformation in GetAllHandles())
            {
                if (handleInformation.ObjectPointer == fileObjectPointer)
                {
                    fileName = GetFilenameOfRemoteHandle(handleInformation);
                    break;
                }
            }

            return fileName;
        }

        private static string GetFilenameOfRemoteHandle(SYSTEM_HANDLE_INFORMATION_EX systemHandleInformation, bool useCache = true)
        {
            IntPtr fileHandle = IntPtr.Zero;
            IntPtr openProcessHandle = IntPtr.Zero;

            if (OBJECT_TYPE_FILE != -1 && systemHandleInformation.ObjectType != OBJECT_TYPE_FILE)
            {
                // this is not even a file
                return null;
            }

            if (useCache)
            {
                // maybe it's already in the cache
                if (filenamesCache.ContainsKey(systemHandleInformation))
                    return filenamesCache[systemHandleInformation];
            }

            string filename = null;
            try
            {
                openProcessHandle = OpenProcess(PROCESS_ACCESS_FLAGS.DupHandle, true, (int)systemHandleInformation.ProcessID);
                if (!DuplicateHandle(openProcessHandle, systemHandleInformation.HandleValue, GetCurrentProcess(), out fileHandle, 0, false,
                    DuplicateHandleOptions.DUPLICATE_SAME_ACCESS))
                {
                    return null;
                }

                FileType fileType = GetFileType(fileHandle);
                if (fileType != FileType.FileTypeDisk && fileType != FileType.FileTypePipe)
                    return null;

                // We know what the type of File is
                OBJECT_TYPE_FILE = systemHandleInformation.ObjectType;

                GetFileNameOfRemoteHandle(systemHandleInformation.HandleValue, (int)systemHandleInformation.ProcessID, out filename);
                return filename;

            }
            finally
            {
                filenamesCache[systemHandleInformation] = filename;

                CloseHandle(fileHandle);
                CloseHandle(openProcessHandle);
            }
        }

        private static bool GetFileNameOfRemoteHandle(IntPtr handle, int processId, out string fileName)
        {
            IntPtr currentProcess = NativeMethods.GetCurrentProcess();
            bool remote = (processId != NativeMethods.GetProcessId(currentProcess));
            SafeProcessHandle processHandle = null;
            SafeObjectHandle objectHandle = null;
            try
            {
                if (remote)
                {
                    processHandle = NativeMethods.OpenProcess(ProcessAccessRights.PROCESS_DUP_HANDLE, true, processId);
                    if (NativeMethods.DuplicateHandle(processHandle.DangerousGetHandle(), handle, currentProcess, out objectHandle, 0, false,
                        DuplicateHandleOptions.DUPLICATE_SAME_ACCESS))
                    {
                        handle = objectHandle.DangerousGetHandle();
                    }
                }
                return GetFileNameOfLocalHandle(handle, out fileName, 200);
            }
            finally
            {
                if (remote)
                {
                    if (processHandle != null)
                    {
                        processHandle.Close();
                    }
                    if (objectHandle != null)
                    {
                        objectHandle.Close();
                    }
                }
            }
        }

        private class FileNameFromHandleState : IDisposable
        {
            private ManualResetEvent _mr;

            public IntPtr Handle { get; }

            public bool IsWaiting { get; set; }

            public string FileName { get; set; }

            public bool RetValue { get; set; }

            public FileNameFromHandleState(IntPtr handle)
            {
                _mr = new ManualResetEvent(false);
                this.Handle = handle;
            }

            public bool WaitOne(int wait)
            {
                this.IsWaiting = true;
                bool returnValue = _mr.WaitOne(wait, false);
                this.IsWaiting = false;
                return returnValue;
            }

            public void Set()
            {
                _mr.Set();
            }
            #region IDisposable Members

            public void Dispose()
            {
                if (_mr != null)
                    _mr.Close();
            }

            #endregion
        }

        private static bool GetFileNameOfLocalHandle(IntPtr handle, out string fileName, int milisecondsTimeout)
        {
            using (FileNameFromHandleState state = new FileNameFromHandleState(handle))
            {
                ThreadPool.QueueUserWorkItem(new WaitCallback(GetFileNameOfLocalHandle), state);
                if (state.WaitOne(milisecondsTimeout))
                {
                    fileName = state.FileName;
                    return state.RetValue;
                }
                else
                {
                    fileName = string.Empty;
                    return false;
                }
            }
        }

        private static void GetFileNameOfLocalHandle(object state)
        {
            FileNameFromHandleState s = (FileNameFromHandleState)state;
            string fileName;
            s.RetValue = GetFileNameOfLocalHandle(s.Handle, out fileName);
            s.FileName = fileName;
            if (s.IsWaiting)
                s.Set();
        }

        private static bool GetFileNameOfLocalHandle(IntPtr handle, out string fileName)
        {
            if (handle.ToInt32() == 0)
            {
                throw new Exception("Handle is null");
            }

            IntPtr ptr = IntPtr.Zero;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                int length = 0x200;  // 512 bytes
                RuntimeHelpers.PrepareConstrainedRegions();
                try { }
                finally
                {
                    // CER guarantees the assignment of the allocated 
                    // memory address to ptr, if an ansynchronous exception 
                    // occurs.
                    ptr = Marshal.AllocHGlobal(length);
                }
                NT_STATUS ret = NtQueryObject(handle, OBJECT_INFORMATION_CLASS.ObjectNameInformation, ptr, length, out length);

                if (ret == NT_STATUS.STATUS_BUFFER_OVERFLOW)
                {
                    RuntimeHelpers.PrepareConstrainedRegions();
                    try { }
                    finally
                    {
                        // CER guarantees that the previous allocation is freed,
                        // and that the newly allocated memory address is 
                        // assigned to ptr if an asynchronous exception occurs.
                        Marshal.FreeHGlobal(ptr);
                        ptr = Marshal.AllocHGlobal(length);
                    }
                    ret = NtQueryObject(handle, OBJECT_INFORMATION_CLASS.ObjectNameInformation, ptr, length, out length);
                }
                if (ret == NT_STATUS.STATUS_SUCCESS)
                {
                    // fileName = Marshal.PtrToStringUni((IntPtr)((int)ptr + 16), (length - 9) / 2);
                    OBJECT_NAME_INFORMATION objObjectName = Marshal.PtrToStructure<OBJECT_NAME_INFORMATION>(ptr);

                    if (objObjectName.Name.Buffer != IntPtr.Zero)
                    {
                        string strObjectName = Marshal.PtrToStringUni(objObjectName.Name.Buffer);
                        fileName = GetRegularFileNameFromDevice(strObjectName);
                        //return strObjectName;
                    }
                    else
                    {
                        fileName = string.Empty;
                    }
                    return fileName.Length != 0;
                }
            }
            finally
            {
                // CER guarantees that the allocated memory is freed, 
                // if an asynchronous exception occurs.
                Marshal.FreeHGlobal(ptr);
            }

            fileName = string.Empty;
            return false;
        }

        private static string GetRegularFileNameFromDevice(string strRawName)
        {
            string strFileName = strRawName;
            foreach (string strDrivePath in Environment.GetLogicalDrives())
            {
                var sbTargetPath = new StringBuilder(MAX_PATH);
                
                if (QueryDosDevice(strDrivePath.Substring(0, 2), sbTargetPath, MAX_PATH) == 0)
                {
                    return strRawName;
                }
                string strTargetPath = sbTargetPath.ToString();
                if (strFileName.StartsWith(strTargetPath))
                {
                    strFileName = strFileName.Replace(strTargetPath, strDrivePath.Substring(0, 2));
                    break;
                }
            }
            return strFileName;
        }

        public static void EnumerateExistingHandles(Process[] processes)
        {
            foreach (SYSTEM_HANDLE_INFORMATION_EX handleInformation in GetAllHandles())
            {
                if (processes.All((p) => p.Id != (int)handleInformation.ProcessID)) continue;

                GetFilenameOfRemoteHandle(handleInformation);
            }
        }

        private static bool IsOneOfProcesses(int testedPID, List<int> legalProcesses)
        {
            // For some reason this is significantly faster than LINQ's All/Any

            bool processIsGood = false;
            foreach (uint pid in legalProcesses)
            {
                if (pid == testedPID)
                {
                    processIsGood = true;
                    break;
                }
            }

            return processIsGood;
        }

        /// <summary>
        /// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry.htm?ts=0,242
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYSTEM_HANDLE_INFORMATION
        { // Information Class 16
            public ushort ProcessID;
            public ushort CreatorBackTrackIndex;
            public byte ObjectType;
            public byte HandleAttribute;
            public ushort Handle;
            public IntPtr Object_Pointer;
            public IntPtr AccessMask;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYSTEM_HANDLE_INFORMATION_EX
        { // Information Class 64
            public IntPtr ObjectPointer;
            public IntPtr ProcessID;
            public IntPtr HandleValue;
            public uint GrantedAccess;
            public ushort CreatorBackTrackIndex;
            public ushort ObjectType;
            public uint HandleAttributes;
            public uint Reserved;
        }

        private enum OBJECT_INFORMATION_CLASS : int
        {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2,
            ObjectAllTypesInformation = 3,
            ObjectHandleInformation = 4
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct OBJECT_NAME_INFORMATION
        { // Information Class 1
            public UNICODE_STRING Name;
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

        private enum FileType : uint
        {
            FileTypeChar = 0x0002,
            FileTypeDisk = 0x0001,
            FileTypePipe = 0x0003,
            FileTypeRemote = 0x8000,
            FileTypeUnknown = 0x0000,
        }

        #region ENUMs
        internal enum NT_STATUS
        {
            STATUS_SUCCESS = 0x00000000,
            STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005L),
            STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004L)
        }

        internal enum SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation = 0,
            SystemPerformanceInformation = 2,
            SystemTimeOfDayInformation = 3,
            SystemProcessInformation = 5,
            SystemProcessorPerformanceInformation = 8,
            SystemHandleInformation = 16,
            SystemInterruptInformation = 23,
            SystemExceptionInformation = 33,
            SystemRegistryQuotaInformation = 37,
            SystemLookasideInformation = 45
        }

        [Flags]
        internal enum ProcessAccessRights
        {
            PROCESS_DUP_HANDLE = 0x00000040
        }

        [Flags]
        internal enum DuplicateHandleOptions
        {
            DUPLICATE_CLOSE_SOURCE = 0x1,
            DUPLICATE_SAME_ACCESS = 0x2
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

        #region Native Methods
        internal static class NativeMethods
        {
            [DllImport("ntdll.dll")]
            internal static extern NT_STATUS NtQuerySystemInformation(
                [In] SYSTEM_INFORMATION_CLASS SystemInformationClass,
                [In] IntPtr SystemInformation,
                [In] int SystemInformationLength,
                [Out] out int ReturnLength);


            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern SafeProcessHandle OpenProcess(
                [In] ProcessAccessRights dwDesiredAccess,
                [In, MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
                [In] int dwProcessId);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool DuplicateHandle(
                [In] IntPtr hSourceProcessHandle,
                [In] IntPtr hSourceHandle,
                [In] IntPtr hTargetProcessHandle,
                [Out] out SafeObjectHandle lpTargetHandle,
                [In] int dwDesiredAccess,
                [In, MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
                [In] DuplicateHandleOptions dwOptions);

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
        }
        #endregion

        [DllImport("ntdll.dll")]
        private static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(PROCESS_ACCESS_FLAGS dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, [In] DuplicateHandleOptions dwOptions);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll")]
        private static extern NT_STATUS NtQueryObject(IntPtr ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength, out int returnLength);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

        [DllImport("kernel32.dll")]
        private static extern bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags);

        [DllImport("kernel32.dll")]
        private static extern FileType GetFileType(IntPtr hFile);

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
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
   uint dwThreadId);

        [DllImport("kernel32.dll")]
        static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll")]
        static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetNamedPipeServerProcessId(IntPtr Pipe, out uint ServerProcessId);

        private const int MAX_PATH = 260;
        private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        private const int DUPLICATE_SAME_ACCESS = 0x2;
        private const uint FILE_SEQUENTIAL_ONLY = 0x00000004;
        private const int CNST_SYSTEM_HANDLE_INFORMATION = 0x10;
        private const int CNST_SYSTEM_HANDLE_INFORMATION_EX = 64;
        private static int OBJECT_TYPE_FILE = -1;
    }

}
