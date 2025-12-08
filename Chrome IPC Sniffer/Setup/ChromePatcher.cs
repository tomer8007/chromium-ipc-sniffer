using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Threading;

namespace ChromiumIPCSniffer
{
    /// <summary>
    /// A class resposible for patching chrome processes, for making IPCZ messages fly over pipes instead of shared memory, when possible and needed
    /// </summary>
    class ChromePatcher
    {
        private Dictionary<int, bool> pidToPatchStatusTable = new Dictionary<int, bool>();

        private long patchOffsetInDll = -1;
        private long TEXT_SECTION_RUNTIME_TO_DISK_DELTA = 0x1000 - 0x600; // .text section VirtualAddress - PointerToRawData = 0xA00.    TODO: read this from PE
        private ChromeMonitor chromeMonitor;

        // .text:0000000183A90311 48 8B 49 10                   mov rcx, [rcx + 10h]
        // .text:0000000183A90315 48 8B 50 10                   mov rdx, [rax + 10h]
        // .text:0000000183A90319 48 3B 51 60                   cmp rdx, [rcx + 60h]
        // .text:0000000183A9031D 0F 85 A0 1B 00 00             jnz loc_183A
        // void RemoteRouterLink::AcceptParcel { ...
        //    parcel->data_fragment_memory() != &node_link()->memory())
        // https://source.chromium.org/chromium/chromium/src/+/main:third_party/ipcz/src/ipcz/remote_router_link.cc;l=247
        public byte[] acceptParcelFuncPattern = { 0x48, 0x8B, 0x49, 0x10, 0x48, 0x8B, 0x50, 0x10, 0x48, 0x3B, 0x51, 0x60 };

        // .text:0000000183A902FA 80 78 30 01       cmp byte ptr[rax + 30h], 1
        // void RemoteRouterLink::AcceptParcel
        //  if (!parcel->has_data_fragment() ||
        // https://source.chromium.org/chromium/chromium/src/+/main:third_party/ipcz/src/ipcz/remote_router_link.cc;l=246;
        public byte[] conditionInstructionToLookFor = { 0x80, 0x78, 0x30, 0x01 };
        public byte[] conditionInstructionToPatch = { 0x80, 0x78, 0x30, 0x09 };

        public ChromePatcher(ChromeMonitor chromeMonitor)
        {
            // TODO: add a check about chrome version
            this.patchOffsetInDll = FindPatchOffset(chromeMonitor.DLLPath);
            this.chromeMonitor = chromeMonitor;
        }

        public long FindPatchOffset(string chromeDllPath)
        {
            Console.WriteLine("[+] Finding IPCZ patching offset in chrome.dll....");
            byte[] chromeDllContents = File.ReadAllBytes(chromeDllPath);
            int[] patternOffsetCandidates = chromeDllContents.Locate(acceptParcelFuncPattern, maxResults: 1);

            int patternOffset = -1;

            foreach (int possibleOffset in patternOffsetCandidates)
            {
                // we are going to assume the first candidate is the real one for now.
                Console.WriteLine("[+] Found patch candidate at offset 0x" + possibleOffset.ToString("X"));
                patternOffset = possibleOffset;
                break;
            }

            if (patternOffset == -1)
            {
                Console.WriteLine("[!] Did not find patch location, skipping");
                return patchOffsetInDll;
            }

            //
            //  Now look for the specific condition we want to pathc
            //
            int[] patchOffsets = chromeDllContents.Locate(conditionInstructionToLookFor, patternOffset - 40, 40);
            if (patchOffsets.Length == 0)
            {
                Console.WriteLine("[!] Did not find condition instruction to patch, skipping");
            }

            patchOffsetInDll = patchOffsets[0];

            return patchOffsetInDll;
        }

        public void StartPatching()
        {
            Console.WriteLine("[+] Starting patching of Chrome processes");

            PatchRunningProcesses();

            // make sure to patch newly created chrome proceses as well
            chromeMonitor.StartMonitoring();
            chromeMonitor.NewChromeProcessCallback += OnNewChromeProcess;

        }

        public void PatchRunningProcesses()
        {
            Process[] chromeProcesses = ChromeMonitor.GetRunningChromeProcesses();
            foreach (Process chromeProcess in chromeProcesses)
            {
                if (pidToPatchStatusTable.ContainsKey(chromeProcess.Id) && pidToPatchStatusTable[chromeProcess.Id] == true)
                    continue; // don't try to patch proceses we patched successfuly earlier

                //Process chromeProcess = null;
                //try
                //{
                //    chromeProcess = Process.GetProcessById(chromePID);
                //}
                //catch (ArgumentException e)
                //{
                //    // process ID not running? maybe it was closed
                //    Console.WriteLine("[!] Skipping PID " + chromePID);
                //    continue;
                //}

                PatchProcess(chromeProcess);
            }
        }

        private void OnNewChromeProcess(Process newProcess)
        {
            Console.WriteLine("[+] Seeing new PID: " + newProcess.Id);
            bool patchSucceeded = TryToPatchProcess(newProcess);
            pidToPatchStatusTable[newProcess.Id] = patchSucceeded;
            PatchRunningProcesses();
        }

        public void Stop()
        {
            this.chromeMonitor.StopMonitoring();
        }

        public bool PatchProcess(Process chromeProcess)
        {
            bool success = TryToPatchProcess(chromeProcess);
            pidToPatchStatusTable[chromeProcess.Id] = success;

            return success;
        }

        public bool TryToPatchProcess(Process chromeProcess)
        {
            if (patchOffsetInDll == -1) return true;

            IntPtr moduleBase = new IntPtr(0);

            int maxAttempts = 3;
            for (int i = 0; i < maxAttempts; i++)
            {
                try
                {
                    moduleBase = chromeProcess.GetModuleBaseAddress("chrome.dll");

                    if (moduleBase == IntPtr.Zero)
                    {
                        // maybe it just wasn't loaded yet
                        // try again
                        Console.WriteLine("[-] Couldn't find chrome.dll in PID " + chromeProcess.Id);
                    }
                }
                catch (Exception e)
                {
                    if (e.Message.Contains("has exited"))
                    {
                        // some new processes are immediately closed, consider this successful
                        return true;
                    }

                    // fail with "only part of a ReadProcessMemory or WriteProcessMemory request was completed"?
                    // assume the process was closed or something (some new processes are immediately closed)
                    // try again
                    Console.WriteLine("[!] skipping patching of PID " + chromeProcess.Id + " because of error: " + e.Message);
                }

                Thread.Sleep(700);
            }

            if (moduleBase == IntPtr.Zero)
            {
                // some chrome processes don't have chrome.dll loaded.
                if (chromeProcess.GetCommandLine().Contains("--type=crashpad-handler"))
                {
                    Console.WriteLine("[!] Giving up on patching crashpad handler PID " + chromeProcess.Id);
                    return true; // consider success
                }

                return false; // try again in the future
            }



            IntPtr patchAddress = new IntPtr(moduleBase.ToInt64() + TEXT_SECTION_RUNTIME_TO_DISK_DELTA + patchOffsetInDll);

            Console.WriteLine("[+] Patching PID " + chromeProcess.Id + " at adress 0x" + patchAddress.ToString("X"));

            byte[] oldMemoryContents = chromeProcess.ReadMemory(patchAddress, this.conditionInstructionToLookFor.Length);
            if (oldMemoryContents == null) return false;

            if (oldMemoryContents[0] != this.conditionInstructionToLookFor[0])
            {
                Console.WriteLine("[-] Unexpected memory in process " + chromeProcess.Id);
                return false;
            }

            bool writeMemorySuccess = chromeProcess.WriteMemory(patchAddress, this.conditionInstructionToPatch);
            if (!writeMemorySuccess) return false;

            byte[] newMemoryContents = chromeProcess.ReadMemory(patchAddress, this.conditionInstructionToLookFor.Length);
            if (oldMemoryContents == null) return false;

            if (newMemoryContents.Last() != this.conditionInstructionToPatch.Last())
            {
                Console.WriteLine("[-] Pathing of PID " + chromeProcess.Id + " was not successful.");
                return false;
            }

            Console.WriteLine("[+] Pathing of PID " + chromeProcess.Id + " was successful.");

            return true;
        }
    }
}
