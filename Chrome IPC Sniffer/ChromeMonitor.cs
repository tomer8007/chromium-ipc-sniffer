﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Management;
using Newtonsoft.Json;
using System.Net;

namespace ChromiumIPCSniffer
{
    public class ChromeMonitor
    {
        // This should be updated whenever a chrome process gets created/destryoed
        private Dictionary<UInt32, ProcessInfo> RunningProcessesCache = new Dictionary<UInt32, ProcessInfo>();

        public string DLLPath = string.Empty;
        public string ChromeVersion = string.Empty;

        public ChromeMonitor(string dllPath = null)
        {
            UpdateRunningProcessesCache();
            InitializeInstance(dllPath);
        }

        public void InitializeInstance(string dllPath = null)
        {
            Console.WriteLine("[+] Determining your chromium version");
            this.DLLPath = dllPath == null ? GetChromeDLLPath() : dllPath;
            
            this.ChromeVersion = GetChromeDLLVersion(this.DLLPath);

            Console.WriteLine("[+] You are using chromium " + this.ChromeVersion);
            //Console.WriteLine("[+] " + this.DLLPath);

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

        }

        public List<int> GetRunningChromePIDs()
        {
            return RunningProcessesCache.Values.Where(processInfo => processInfo.Name.Contains("chrome")).Select(processInfo => processInfo.PID).ToList();
        }

        public void UpdateRunningProcessesCache()
        {
            Process[] runningProcesses = Process.GetProcesses();
            foreach (Process process in runningProcesses)
            {
                ProcessInfo processInfo;
                processInfo.PID = process.Id;
                processInfo.Name = process.ProcessName;
                processInfo.CommandLine = processInfo.Name == "chrome" ? process.GetCommandLine() : "";
                RunningProcessesCache[(UInt32)process.Id] = processInfo;
            }
        }

        public bool IsChromeProcess(UInt32 pid)
        {
            if (RunningProcessesCache.ContainsKey(pid))
            {
                return RunningProcessesCache[pid].Name == "chrome";
            }
            else
            {
                return false;
            }
        }

        public ChromeProcessType GetChromeProcessType(UInt32 chromePID)
        {
            string commandLine = null;
            string processName = null;

            if (RunningProcessesCache.ContainsKey(chromePID))
            {
                commandLine = RunningProcessesCache[chromePID].CommandLine;
                processName = RunningProcessesCache[chromePID].Name;
            }
            else
            {
                return ChromeProcessType.Unknown;
            }

            ChromeProcessType type = ChromeProcessType.Unknown;

            // Some sanity checks
            if (processName != "chrome") return type;
            if (commandLine == null) return type;

            if (!commandLine.Contains("--type=")) type = ChromeProcessType.Broker;
            else if (commandLine.Contains("--extension-process") && !commandLine.Contains("--disable-databases")) type = ChromeProcessType.Extension;
            else if (commandLine.Contains("--type=watcher")) type = ChromeProcessType.Watcher;
            else if (commandLine.Contains("--utility-sub-type=audio.mojom.AudioService")) type = ChromeProcessType.AudioService;
            else if (commandLine.Contains("--utility-sub-type=network.mojom.NetworkService")) type = ChromeProcessType.NetworkService;
            else if (commandLine.Contains("--service-sandbox-type=cdm")) type = ChromeProcessType.ContentDecryptionModuleService;
            else if (commandLine.Contains("--type=gpu-process")) type = ChromeProcessType.GpuProcess;
            else if (commandLine.Contains("--type=renderer")) type = ChromeProcessType.Renderer;

            return type;
        }

        private bool ProcessExists(UInt32 pid)
        {
            UpdateRunningProcessesCache();

            return RunningProcessesCache.ContainsKey(pid);
        }

        public enum ChromeProcessType
        {
            Unknown = 0,
            Broker,
            Renderer,
            Extension,
            Notification,
            Plugin,
            Worker,
            NCAL,
            GpuProcess,
            Watcher,
            ServiceWorker,
            NetworkService,
            AudioService,
            ContentDecryptionModuleService,
            CrashpadHandler,
            PpapiBroker,
        }

        public static Process[] GetRunningChromeProcesses()
        {
            return Process.GetProcessesByName("chrome");
        }

        public static string GetChromeDLLPath()
        {
            //
            // Search for a chrome process that has chrome.dll loaded in
            //
            try
            {
                foreach (Process chromeProcess in Process.GetProcessesByName("chrome"))
                {
                    ProcessModuleCollection chromeModules = chromeProcess.Modules;
                    foreach (ProcessModule module in chromeModules)
                    {
                        if (module.FileName.EndsWith("chrome.dll"))
                        {
                            return module.FileName;
                        }
                    }
                }
            }
            catch (Exception)
            {
                // well, try to use the fallback method.
            }

            //
            // Look in Program Fies manually.
            //

            string programFilesDirX86 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Google\Chrome\Application");
            string programFilesDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Google\Chrome\Application");

            if (Directory.Exists(programFilesDirX86)) programFilesDir = programFilesDirX86;

            if (Directory.Exists(programFilesDir))
            {
                List<Version> chromeVersions = new DirectoryInfo(programFilesDir).GetDirectories().Where(info => info.Name.Contains("."))
                    .Select(info => new Version(info.Name)).ToList();

                chromeVersions.Sort();
                chromeVersions.Reverse();

                string chromeDllPath = Path.Combine(programFilesDir, chromeVersions[0].ToString(), "chrome.dll");
                if (File.Exists(chromeDllPath)) return chromeDllPath;
            }

            Console.WriteLine("[-] Could not find chrome.dll. Aborting.");
            Environment.Exit(1);

            return "";
        }

        public static string GetChromeDLLVersion(string chrmeDLLPath)
        {
            try
            {
                FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(chrmeDLLPath);
                string version = versionInfo.FileVersion; // Will typically return "1xx.xxx.xxx" 
                if (version.Contains("."))
                {
                    return version;
                }
            }
            catch
            {
                // fallback to Directory path
            }

            return new DirectoryInfo(Path.GetDirectoryName(chrmeDLLPath)).Name;

        }

        public static string GetCommitForVersion(string chromeVersion)
        {
            using (var webClient = new WebClient())
            {
                webClient.Headers.Add("User-Agent", "Chrome IPC Sniffer");
 
                string refUrl = $"https://api.github.com/repos/chromium/chromium/git/ref/tags/{chromeVersion}";
                dynamic gitRef = JsonConvert.DeserializeObject(webClient.DownloadString(refUrl));

                if ((string)gitRef.@object.type == "commit")
                    return gitRef.@object.sha;

                if ((string)gitRef.@object.type == "tag")
                {
                    string tagUrl = (string)gitRef.@object.url;
                    dynamic tagObj = JsonConvert.DeserializeObject(webClient.DownloadString(tagUrl));
                    return tagObj.@object.sha;
                }

                throw new InvalidOperationException("Unknown tag object type.");
            }
        }
    }

    public struct ProcessInfo
    {
        public string Name;
        public int PID;
        public string CommandLine;
    }
}
