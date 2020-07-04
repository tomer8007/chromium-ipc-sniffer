using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace ChromeIPCSniffer
{
    public class NamedPipeInfo
    {
        public List<ulong> FileObjects { get; set; }
        public string PipeFileName { get; set; }

        public List<UInt32> InvolvedProcesses { get; set; }
        public UInt32 CreatingPID { get; set; }

        public bool isSkipping = false;

        public NamedPipeInfo(UInt64 fileIdentifier, string pipeName, UInt32 firstPID)
        {
            this.FileObjects = new List<ulong> { fileIdentifier };
            this.InvolvedProcesses = new List<UInt32>();
            this.InvolvedProcesses.Add(firstPID);
            this.CreatingPID = firstPID;
            this.PipeFileName = pipeName;
        }

        public void AddProcessIfNeeded(UInt32 PID)
        {
            if (!this.InvolvedProcesses.Contains(PID))
            {
                this.InvolvedProcesses.Add(PID);
            }
        }

        public void AddFileObjectIfNeeded(UInt64 fileObject)
        {
            if (!this.FileObjects.Contains(fileObject))
            {
                this.FileObjects.Add(fileObject);
            }
        }

        public List<UInt32> GetInvolvedProcesses()
        {
            List<UInt32> involvedPIDs  = new List<uint>();
            using (NamedPipeClientStream pipeClient = new NamedPipeClientStream(this.PipeFileName))
            {
                pipeClient.Connect();
                IntPtr handle = pipeClient.SafePipeHandle.DangerousGetHandle();
                GetNamedPipeClientProcessId(handle, out uint clientPID);
                GetNamedPipeServerProcessId(handle, out uint serverPID);

                involvedPIDs.Add(clientPID);
                involvedPIDs.Add(serverPID);
            }

            return involvedPIDs;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetNamedPipeServerProcessId(IntPtr Pipe, out uint ServerProcessId);
    }
}
