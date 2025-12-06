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

            List<int> chromePIDs = chromeMonitor.GetRunningChromePIDs();
            foreach (int chromePID in chromePIDs)
            {
                try
                {
                    Process chromeProcess = Process.GetProcessById(chromePID);
                    PatchProcess(chromeProcess);
                }
                catch (ArgumentException e)
                {
                    // process ID not running? maybe it was closed
                    continue;
                }

            }

            // make sure to patch newly created chrome proceses as well
            chromeMonitor.StartMonitoring();
            chromeMonitor.NewChromeProcessCallback += OnNewChromeProcess;

        }

        private void OnNewChromeProcess(Process newProcess)
        {
            PatchProcess(newProcess);
        }

        public void Stop()
        {
            this.chromeMonitor.StopMonitoring();
        }

        public bool PatchProcess(Process chromeProcess)
        {
            if (patchOffsetInDll == -1) return true;

            Console.WriteLine("[+] Patching PID " + chromeProcess.Id);

            long moduleBase = chromeMonitor.GetChromeModuleAddress(chromeProcess);
            if (moduleBase == 0)
            {
                //Console.WriteLine("[!] skipping patching of PID " + chromeProcess.Id);
                return false;
            }

            long patchAddress = moduleBase + TEXT_SECTION_RUNTIME_TO_DISK_DELTA + patchOffsetInDll;

            byte[] oldMemoryContents = chromeProcess.ReadMemory(new IntPtr(patchAddress), this.conditionInstructionToLookFor.Length);
            if (oldMemoryContents == null)
                return false;

            if (oldMemoryContents[0] != this.conditionInstructionToLookFor[0])
            {
                Console.WriteLine("[-] Unexpected memory in process " + chromeProcess.Id);
                return false;
            }

            return chromeProcess.WriteMemory(new IntPtr(patchAddress), this.conditionInstructionToPatch);
        }
    }
}
