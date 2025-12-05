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
        private long patchOffset = -1;
        private long TEXT_SECTION_RUNTIME_TO_DISK_DELTA = 0x1000 - 0x600; // .text section VirtualAddress - PointerToRawData = 0xA00.    TODO: read this from PE
        private ChromeMonitor chromeMonitor;

        public ChromePatcher(ChromeMonitor chromeMonitor)
        {
            // TODO: add a check about chrome version
            this.patchOffset = FindPatchOffset(chromeMonitor.DLLPath);
            this.chromeMonitor = chromeMonitor;
        }

        // .text:0000000183A902F7 48 8B 00          mov     rax, [rax]
        // .text:0000000183A902FA 80 78 30 01       cmp byte ptr[rax + 30h], 1
        // .text:0000000183A902FE 4C 89 A4 24 88 00+mov[rsp + 5A8h + var_520]
        // .text:0000000183A90306 0F 85 B7 1B 00 00 jnz     loc_183A91EC3
        // void RemoteRouterLink::AcceptParcel
        //  if (!parcel->has_data_fragment() ||
        // https://source.chromium.org/chromium/chromium/src/+/main:third_party/ipcz/src/ipcz/remote_router_link.cc;l=246;

        public byte[] patternToLookFor = { 0x48, 0x8B, 0x00, 0x80, 0x78, 0x30, 0x01 };
        public byte[] patternToPatch = { 0x48, 0x8B, 0x00, 0x80, 0x78, 0x30, 0x09 };

        public long FindPatchOffset(string chromeDllPath)
        {
            Console.WriteLine("[+] Finding IPCZ patching offset in chrome.dll....");
            byte[] chromeDll = File.ReadAllBytes(chromeDllPath);
            int[] patchOffsetCandidates = chromeDll.Locate(patternToLookFor, maxResults: 1);

            foreach (int patchLocation in patchOffsetCandidates)
            {
                // we are going to assume the first candidate is the real one for now.
                Console.WriteLine("[+] Found patch candidate at offset 0x" + patchLocation.ToString("X"));
                patchOffset = patchLocation;
                break;
            }

            if (patchOffset == -1)
            {
                Console.WriteLine("[!] Did not find patch location, skipping");
            }

            return patchOffset;
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
            if (patchOffset == -1) return true;

            Console.WriteLine("[+] Patching PID " + chromeProcess.Id);

            long moduleBase = chromeMonitor.GetChromeModuleAddress(chromeProcess);
            if (moduleBase == 0)
            {
                //Console.WriteLine("[!] skipping patching of PID " + chromeProcess.Id);
                return false;
            }

            long patchAddress = moduleBase + TEXT_SECTION_RUNTIME_TO_DISK_DELTA + patchOffset;

            byte[] oldMemoryContents = chromeProcess.ReadMemory(new IntPtr(patchAddress), patternToLookFor.Length);
            if (oldMemoryContents == null)
                return false;

            if (oldMemoryContents[0] != this.patternToLookFor[0])
            {
                Console.WriteLine("[-] Unexpected memory in process " + chromeProcess.Id);
                return false;
            }

            return chromeProcess.WriteMemory(new IntPtr(patchAddress), patternToPatch);
        }
    }
}
