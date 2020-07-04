using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.ServiceProcess;
using ChromeIPCSniffer.Utilities;
using ChromeIPCSniffer.Extensions;

namespace ChromeIPCSniffer
{
    public class TDevMonitor
    {
        public static string SERVICE_NAME = "tdevmonc";
        public static string DRIVER_NAME = "tdevmonc.sys";

        public static int DM_IOCTL_GET_VERSION = DM_CTL_CODE(1);
        public static int DM_IOCTL_GET_TARGET_DEVICE_INFO = DM_CTL_CODE(5);
        public static int DM_IOCTL_CONNECT = DM_CTL_CODE(12);
        public static int DM_IOCTL_DISCONNECT = DM_CTL_CODE(8);
        public static int DM_IOCTL_ENABLE = DM_CTL_CODE(14);
        public static int DM_IOCTL_DISABLE = DM_CTL_CODE(15);
        public static int DM_IOCTL_SET_READ_MODE = DM_CTL_CODE(17);
        public static int DM_IOCTL_SET_FILE_NAME_FILTER = DM_CTL_CODE(19);
        public static int DM_IOCTL_SET_PENDING_NOTIFY_SIZE_LIMIT = DM_CTL_CODE(21);
        public static int DM_IOCTL_STOP = DM_CTL_CODE(9);

        private SafeFileHandle DeviceHandle = null;

        public StreamReader NotificationsStream { get; set; }
        public dm_ReadMode ReadMode { get; set; }

        public TDevMonitor()
        {
            StartTdevDriverIfNeeded();

            IntPtr fileHandle = CreateFile("\\\\.\\tdevmon-master", GENERIC_READ | GENERIC_WRITE, 0, (IntPtr)0, OPEN_EXISTING, 0, NULL);
            this.DeviceHandle = new SafeFileHandle(fileHandle, true);
            if (this.DeviceHandle.IsInvalid)
            {
                int lastError = Marshal.GetLastWin32Error();
                throw new Exception("Could not open a handle to the sniffing driver. Error: " + lastError + ", " + new Win32Exception(lastError).Message);
            }

            if (this.DeviceHandle.IsInvalid)
            {
                Console.WriteLine("Cannot open the driver! Error code: {0}", Marshal.GetLastWin32Error());
                return;
            }

            this.NotificationsStream = null; // by default
            this.ReadMode = dm_ReadMode.dm_ReadMode_Stream;
        }

        public void StartTdevDriverIfNeeded()
        {
            bool isServiceInstalled = NativeServiceInstaller.ServiceIsInstalled(SERVICE_NAME);
            ServiceController tdevmonService = null;

            if (isServiceInstalled)
            {
                tdevmonService = new ServiceController(SERVICE_NAME);

                // uninstall if driver does not really exist
                if (!File.Exists(tdevmonService.GetImagePath()))
                {
                    if (tdevmonService.CanStop) tdevmonService.Stop();
                    NativeServiceInstaller.Uninstall(SERVICE_NAME);
                    isServiceInstalled = false;
                }
            }

            if (!isServiceInstalled)
            {
                Console.WriteLine("[+] Installing the tdevmonc driver");
                NativeServiceInstaller.InstallAndStart(SERVICE_NAME, "Tibbo Device Monitor kernel-mode core service", Path.GetFullPath(DRIVER_NAME),
                                                        isDriver: true, startType: NativeServiceInstaller.ServiceBootFlag.DemandStart);

                tdevmonService = new ServiceController(SERVICE_NAME);
            }

            if (tdevmonService.Status != ServiceControllerStatus.Running)
            {
                Console.WriteLine("[+] Starting the sniffing driver");
                tdevmonService.Start();
            }

            tdevmonService.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMilliseconds(1000));
        }

        public StreamReader StartMonitoringDevice(string deviceName, string filenameFilter = "")
        {
            int bytesReturned = new int();
            bool success = false;

            byte[] sOutput = new byte[512];
            byte[] Input = Encoding.Unicode.GetBytes(deviceName).Concat(new List<byte> { 0, 0 }).ToArray();

            // CONNECT
            success = DeviceIoControl(this.DeviceHandle, DM_IOCTL_CONNECT, Input, Input.Length, sOutput, sOutput.Length, ref bytesReturned, 0);
            if (!success)
            {
                int lastError = Marshal.GetLastWin32Error();
                throw new Exception("[-] Could not send IOCTL CONNECT: Error " + lastError + " (" + new Win32Exception(lastError).Message + ")");
            }

            // SET_READ_MODE
            Input = BitConverter.GetBytes((UInt32)this.ReadMode);
            success = DeviceIoControl(this.DeviceHandle, DM_IOCTL_SET_READ_MODE, Input, Input.Length, sOutput, sOutput.Length, ref bytesReturned, 0);
            if (!success)
            {
                throw new Exception("[-] Could not send IOCTL SET_READ_MODE");
            }

            // SET_FILE_NAME_FILTER
            if (filenameFilter != "")
                Input = Encoding.Unicode.GetBytes(filenameFilter).Concat(new List<byte> { 0, 0 }).ToArray();
            else
                Input = new byte[] { };
            success = DeviceIoControl(this.DeviceHandle, DM_IOCTL_SET_FILE_NAME_FILTER, Input, Input.Length, sOutput, sOutput.Length, ref bytesReturned, 0);
            if (!success)
            {
                throw new Exception("[-] Could not send IOCTL SET_FILE_NAME_FILTER");
            }

            // SET_PENDING_NOTIFY_SIZE_LIMIT
            // TODO: Are we not processing packets fast enough?
            int pendingNotifyLimit = 1048576 * 32;
            Input = BitConverter.GetBytes(pendingNotifyLimit);
            success = DeviceIoControl(this.DeviceHandle, DM_IOCTL_SET_PENDING_NOTIFY_SIZE_LIMIT, Input, Input.Length, sOutput, sOutput.Length, ref bytesReturned, 0);
            if (!success)
            {
                throw new Exception("[-] Could not send IOCTL SET_PENDING_NOTIFY_SIZE_LIMIT");
            }

            // ENABLE
            Input = new byte[] { };
            success = DeviceIoControl(this.DeviceHandle, DM_IOCTL_ENABLE, Input, Input.Length, sOutput, sOutput.Length, ref bytesReturned, 0);
            if (!success)
            {
                throw new Exception("[-] Could not send IOCTL ENABLE");
            }

            this.NotificationsStream = new StreamReader(new FileStream(this.DeviceHandle, FileAccess.Read, 4096, false), Encoding.Default, true, 4096);

            return this.NotificationsStream;
        }

        public void Stop()
        {
            int bytesReturned = new int();
            bool success = false;

            byte[] sOutput = new byte[512];
            byte[] Input = new byte[] { 0, 0, 0, 0 };

            // DISCONNECT
            success = DeviceIoControl(this.DeviceHandle, DM_IOCTL_DISCONNECT, Input, Input.Length, sOutput, sOutput.Length, ref bytesReturned, 0);
            if (!success)
            {
                int lastError = Marshal.GetLastWin32Error();
            }

            this.DeviceHandle.Close();
        }


        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct dm_NotifyHdr
        {
            public UInt32 signature;
            public ushort code;
            public ushort flags;
            public UInt32 ntStatus;
            public UInt32 paramSize;
            public UInt32 processId;
            public UInt32 threadId;
            public UInt64 timestamp;

            // followed by params
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct dm_ReadWriteNotifyParams
        {
            public UInt64 fileIdentifier;
            public UInt64 offset;
            public UInt32 bufferSize;
            public UInt32 dataSize;

            // followed by read/write data
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct dm_CreateNotifyParams
        {
            public UInt64 fileIdentifier;

            public UInt32 options;
            public UInt32 desiredAccess;
            public UInt32 shareAccess;
            public UInt32 fileAttributes;
            public UInt32 fileNameLength;
            public UInt32 padding;

            // followed by UTF16 file name
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct dm_CreateNamedPipeNotifyParams
        {
            public dm_CreateNotifyParams createParams;
            public UInt32 pipeType;
            public UInt32 readMode;
            public UInt32 completionMode;
            public UInt32 maxInstanceCount;
            public UInt32 inBoundQuota;
            public UInt32 outBoundQuota;
            public UInt64 defaultTimeout;

            // followed by UTF16 pipe name
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct dm_CloseNotifyParams
        {
            public UInt64 fileId;
        };

        public enum dm_NotifyCode
        {
            dm_NotifyCode_Undefined = 0,
            dm_NotifyCode_PnpStartDevice,
            dm_NotifyCode_PnpStopDevice,
            dm_NotifyCode_PnpRemoveDevice,
            dm_NotifyCode_FastIoDetachDevice,
            dm_NotifyCode_Create,
            dm_NotifyCode_CreateNamedPipe,
            dm_NotifyCode_Close,
            dm_NotifyCode_Read,
            dm_NotifyCode_Write,
            dm_NotifyCode_Ioctl,
            dm_NotifyCode_InternalIoctl,
            dm_NotifyCode_Fsctl,
            dm_NotifyCode_CreateMailslot,
            dm_NotifyCode_KeyboardEvent,
            dm_NotifyCode_MouseEvent,
            dm_NotifyCode_FastIoRead,
            dm_NotifyCode_FastIoWrite,
            dm_NotifyCode_FastIoIoctl,
            dm_NotifyCode_DataDropped, // a dedicated notification code
            dm_NotifyCode__Count,
        };

        public enum dm_NotifyFlag
        {
            dm_NotifyFlag_InsufficientBuffer = 0x01, // buffer is not big enough, resize and try again
            dm_NotifyFlag_DataDropped = 0x02, // one or more notifications after this one were dropped
            dm_NotifyFlag_Timestamp = 0x04, // this notification is timestamped
        };

        public enum dm_ReadMode
        {
            dm_ReadMode_Undefined = 0,
            dm_ReadMode_Stream,
            dm_ReadMode_Message,
        };

        // relevant Win32 Methods

        public const int INVALID_HANDLE_VALUE = (-1),
                            NULL = 0,
                            ERROR_SUCCESS = 0,
                            FILE_READ_DATA = (0x0001),
                            FILE_SHARE_READ = 0x00000001,
                            OPEN_EXISTING = 3,
                            GENERIC_READ = unchecked((int)0x80000000),
                            GENERIC_WRITE = unchecked((int)0x40000000),
                            METHOD_BUFFERED = 0,
                            METHOD_NEITHER = 3,
                            FILE_ANY_ACCESS = 0,
                            FILE_DEVICE_VIRTUAL_DISK = 0x00000024;

        [DllImport("Kernel32.dll", ExactSpelling = true, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CloseHandle(int hHandle);

        // CreateFile is is Overloaded for having SecurityAttributes or not 

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(String lpFileName, int dwDesiredAccess, int dwShareMode, IntPtr lpSecurityAttributes, int dwCreationDisposition, int dwFlagsAndAttributes, int hTemplateFile);

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(String lpFileName, int dwDesiredAccess, int dwShareMode, SECURITY_ATTRIBUTES lpSecurityAttributes, int dwCreationDisposition, int dwFlagsAndAttributes, int hTemplateFile);

        // DeviceIoControl is Overloaded for byte or int data

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool DeviceIoControl(SafeFileHandle hDevice, int dwIoControlCode, byte[] InBuffer, int nInBufferSize, byte[] OutBuffer, int nOutBufferSize, ref int pBytesReturned, int pOverlapped);

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool DeviceIoControl(SafeFileHandle hDevice, int dwIoControlCode, int[] InBuffer, int nInBufferSize, int[] OutBuffer, int nOutBufferSize, ref int pBytesReturned, int pOverlapped);

        // These replace Macros in winioctl.h

        public static int CTL_CODE(int DeviceType, int Function, int Method, int Access)
        {
            return (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method));
        }
        public static int DM_CTL_CODE_EX(int code, int method)
        {
            int deviceType = 0x00000022;
            return CTL_CODE(deviceType, 0x800 + code, method, FILE_ANY_ACCESS);
        }
        public static int DM_CTL_CODE(int code)
        {
            return DM_CTL_CODE_EX(code, METHOD_BUFFERED);
        }

        public int DEVICE_TYPE_FROM_CTL_CODE(int ctrlCode)
        {
            return (int)((ctrlCode & 0xffff0000) >> 16);
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;             // DWORD
            public IntPtr lpSecurityDescriptor;    // LPVOID
            public int bInheritHandle;        // BOOL
        }
    }
}
