using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Reflection;
using ChromiumIPCSniffer.Mojo;

namespace ChromiumIPCSniffer
{
    public static class Program
    {
        public static string WIRESHARK_DIR = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Wireshark");
        public static string WIRESHARK_PLUGINS_DIR = Path.Combine(WIRESHARK_DIR, "Plugins");

        static void Main(string[] args)
        {
            Console.WriteLine();
            Console.WriteLine("Chrome IPC Sniffer v" + Assembly.GetExecutingAssembly().GetName().Version.ToString());
            Console.WriteLine();

            //
            // Parse the arguments
            //
            bool onlyNewPipes = false;
            bool forceFetchInterfacesInfo = false;
            bool forceExtractMethodNames = false;
            bool onlyMojo = false;
            foreach (string argument in args)
            {
                if (argument.Contains("--update-interfaces-info")) { forceFetchInterfacesInfo = true; forceExtractMethodNames = true; }
                else if (argument.Contains("--only-new-mojo-pipes")) onlyNewPipes = true;
                else if (argument.Contains("--extract-method-names")) forceExtractMethodNames = true;
                else if (argument.Contains("--only-mojo")) onlyMojo = true;
                else if (argument.Contains("-h") || argument.Contains("--help") || argument.Contains("/?")) { ShowUsage(); return; }
                else
                {
                    Console.WriteLine("[!] Unrecognized argument '{0}'", argument);
                    return;
                }
            }

            Console.WriteLine("Type -h to get usage help and extended options");
            Console.WriteLine();

            Console.WriteLine("[+] Starting up");

            //
            // Prepare
            //

            ChromeMonitor chromeMonitor = new ChromeMonitor();
            string mojoVersion = InterfacesFetcher.UpdateInterfacesInfoIfNeeded(chromeMonitor.ChromeVersion, force: forceFetchInterfacesInfo);
            string legacyIpcversion = LegacyIpcInterfacesFetcher.UpdateInterfacesInfoIfNeeded(chromeMonitor.ChromeVersion, force: forceFetchInterfacesInfo);
            if (mojoVersion != chromeMonitor.ChromeVersion || legacyIpcversion != chromeMonitor.ChromeVersion)
            {
                Console.WriteLine("[!] Cached info is for " + mojoVersion + ", you may run --update-interfaces-info");
            }

            MethodHashesExtractor.ExtractMethodNames(chromeMonitor.DLLPath, force: forceExtractMethodNames);

            bool success = UpdateWiresharkConfiguration();
            if (!success) return;

            Console.WriteLine("[+] Enumerating existing chrome pipes");
            HandlesUtility.EnumerateExistingHandles(ChromeMonitor.GetRunningChromeProcesses());

            //
            // Start sniffing
            //

            string outputPipeName = "chromeipc";
            string outputPipePath = @"\\.\pipe\" + outputPipeName;
            Console.WriteLine("[+] Starting sniffing of chrome named pipe to " + outputPipePath + ".");

            NamedPipeSniffer pipeMonitor = new NamedPipeSniffer(chromeMonitor, outputPipeName, onlyMojo ? "mojo" : "", onlyNewPipes);
            bool isMonitoring = pipeMonitor.Start();

            if (isMonitoring)
            {
                if (Process.GetProcessesByName("Wireshark").Length == 0)
                {
                    Console.WriteLine("[+] Opening Wirehark");
                    Process.Start(@"C:\Program Files\Wireshark\Wireshark.exe", "-k -i " + outputPipePath);
                }

                Console.WriteLine("[+] Capturing packets...");
            }

            //
            // Set up clean up routines
            //
            Console.CancelKeyPress += delegate
            {
                Thread.CurrentThread.IsBackground = false;
                pipeMonitor.Stop();
            };

        }

        static void ShowUsage()
        {
            Console.WriteLine(
            @"Syntax: chromeipc [options]
Available options:

    Capturing:
        --only-mojo
            Records only packets sent over a ""\\mojo.*"" pipe (without ""\\chrome.sync.*"", etc.).

        --only-new-mojo-pipes
            Records only packets sent over mojo AND newly-created pipes since the start of the capture
            This helps reducing noise and it might improve performance
            (example: opening a new tab will create a new mojo pipe).
            
    Interface resolving:
        --update-interfaces-info
            Forcefully re-scan the chromium sources (from the internet) and populate the *_interfaces.json files.
            This might take a few good minutes. Use this if you see wrong interfaces info and wish to update

        --extract-method-names
            Forcefully re-scan chrome.dll file to find the message IDs and update the mojo_interfaces_map.lua file
            This should happen automaticlly whenever chrome.dll changes.
                            ");

        }

        static bool UpdateWiresharkConfiguration()
        {
            if (!Directory.Exists(WIRESHARK_DIR))
            {
                Console.WriteLine("[-] Could not find Wireshark data directory at " + WIRESHARK_DIR);
                Console.WriteLine("[-] Make sure you have Wireshark installed.");

                return false;
            }
            else if (!Directory.Exists(WIRESHARK_PLUGINS_DIR))
            {
                // We should probably just create the plugins directory
                Directory.CreateDirectory(WIRESHARK_PLUGINS_DIR);
            }

            Console.WriteLine("[+] Copying LUA dissectors to Wirehsark plugins directory");

            DirectoryExtensions.CopyDirectory("Dissectors", WIRESHARK_PLUGINS_DIR, true);

            //
            // Configure protocol colors
            //
            string colorfiltersFile = Path.Combine(WIRESHARK_DIR, "colorfilters");
            if (!File.Exists(colorfiltersFile)) colorfiltersFile = @"C:\Program Files\Wireshark\colorfilters";
            if (!File.Exists(colorfiltersFile))
            {
                Console.WriteLine("[!] Could not find Wireshark's colorfilters file, skipping color configuration");

                return true;
            }

            if (!File.ReadAllText(colorfiltersFile).Contains("@mojouser") || true)
            {
                Console.WriteLine("[+] Configuring Wirehsark protocol colors");

                try
                {
                    File.AppendAllText(colorfiltersFile,
                        @"@Mojo Data@mojodata@[65278,65535,53456][0,0,0]
    @Legacy IPC@legacyipc@[64764,57568,65535][0,0,0]
    @Mojo User@mojouser@[56026,61166,65535][0,0,0]
    @Mojo@mojo@[58596,65535,51143][0,0,0]
    @IPCZ@ipcz@[57054,65535,58082][0,0,0]
    @NPFS@npfs@[59367,59110,65535][0,0,0]");

                    //@IPCZ@ipcz@[57054,65535,58082][0,0,0]
                }
                catch (Exception)
                {
                    Console.WriteLine("[!] Could not edit colorfilters, skipping.");
                }
            }

            return true;
        }
    }
}
