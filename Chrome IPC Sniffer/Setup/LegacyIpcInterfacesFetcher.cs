using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Newtonsoft.Json;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Collections;

namespace ChromiumIPCSniffer
{
    /// <summary>
    /// This class fetches Chrome's source code to get information about all the legacy IPC interfaces that exist.
    /// It uses chromium.googlesource.com
    /// </summary>
    public class LegacyIpcInterfacesFetcher
    {
        public static string CACHE_FILENAME = @"Dissectors/helpers/legacy_ipc_interfaces.json";
        public static Dictionary<IPCMessageStart, string> messageFiles = new Dictionary<IPCMessageStart, string>
        {
            { IPCMessageStart.FrameMsgStart, @"content/common/frame_messages.h"},
            { IPCMessageStart.TestMsgStart, @"ipc/ipc_sync_message_unittest.h"},
            { IPCMessageStart.WorkerMsgStart, @"ipc/ipc_channel_proxy_unittest_messages.h"},
            { IPCMessageStart.NaClMsgStart, @"components/nacl/common/nacl_messages.h"},
            { IPCMessageStart.GpuChannelMsgStart, @"gpu/ipc/common/gpu_messages.h"},
            { IPCMessageStart.MediaMsgStart, @"media/gpu/ipc/common/media_messages.h"},
            { IPCMessageStart.PpapiMsgStart, @"ppapi/proxy/ppapi_messages.h"},
            { IPCMessageStart.ChromeMsgStart, @"chrome/common/render_messages.h"},
            { IPCMessageStart.PrintMsgStart, @"components/printing/common/print_messages.h"},
            { IPCMessageStart.ExtensionMsgStart, @"extensions/common/extension_messages.h"},
            { IPCMessageStart.ChromotingMsgStart, @"remoting/host/chromoting_messages.h"},
            { IPCMessageStart.AndroidWebViewMsgStart, @"android_webview/common/render_view_messages.h"},
            { IPCMessageStart.NaClHostMsgStart, @"components/nacl/common/nacl_host_messages.h"},
            { IPCMessageStart.EncryptedMediaMsgStart, @"components/cdm/common/cdm_messages_android.h"},
            { IPCMessageStart.GinJavaBridgeMsgStart, @"content/common/gin_java_bridge_messages.h"},
            { IPCMessageStart.ChromeUtilityPrintingMsgStart, @"chrome/common/chrome_utility_printing_messages.h"},
            { IPCMessageStart.ExtensionsGuestViewMsgStart, @"extensions/common/guest_view/extensions_guest_view_messages.h"},
            { IPCMessageStart.GuestViewMsgStart, @"components/guest_view/common/guest_view_messages.h"},
            { IPCMessageStart.MediaPlayerDelegateMsgStart, @"content/common/media/media_player_delegate_messages.h"},
            { IPCMessageStart.ExtensionWorkerMsgStart, @"extensions/common/extension_messages.h"},
            { IPCMessageStart.SubresourceFilterMsgStart, @"components/subresource_filter/content/common/subresource_filter_messages.h"},
            { IPCMessageStart.UnfreezableFrameMsgStart, @"content/common/unfreezable_frame_messages.h"},
        };

        /// <summary>
        /// Downloads and analyses the legacy IPC files from the chromium git repository,
        /// in case a cache does not exist
        /// </summary>
        /// <param name="force"></param>
        /// <returns>The cached interfaces chromium verison</returns>
        public static string UpdateInterfacesInfoIfNeeded(string chromeVersion, bool force = false)
        {
            if (!force)
            {
                Console.WriteLine("[+] Checking legacy IPC interfaces information");
                if (File.Exists(CACHE_FILENAME))
                {
                    dynamic interfaceInfo = JsonConvert.DeserializeObject(File.ReadAllText(CACHE_FILENAME));
                    string cachedVersion = interfaceInfo["metadata"]["version"];
                    return cachedVersion;
                }
            }

            string commit = ChromeMonitor.GetCommitForVersion(chromeVersion);
            Console.WriteLine("[+] Matching commit is " + commit);

            DownloadAndAnalyzeLegacyIpcFiles(messageFiles, commit, chromeVersion);

            return chromeVersion;
        }

        /// <summary>
        /// Iterates the given legacy IPC file paths, downloads them, extracts interfaces information,
        /// and writes the results to a file
        /// </summary>
        /// <param name="commit"></param>
        /// <param name="chromeVersion"></param>
        public static void DownloadAndAnalyzeLegacyIpcFiles(Dictionary<IPCMessageStart, string> legacyIpcFiles, string commit, string chromeVersion)
        {
            TextWriter textWriter = new StreamWriter(CACHE_FILENAME, false);
            JsonWriter jsonWriter = new JsonTextWriter(textWriter);
            jsonWriter.Formatting = Formatting.Indented;
            jsonWriter.WriteStartObject();

            jsonWriter.WritePropertyName("metadata");
            jsonWriter.WriteStartObject();
            jsonWriter.WritePropertyName("version"); jsonWriter.WriteValue(chromeVersion);
            jsonWriter.WritePropertyName("commit"); jsonWriter.WriteValue(commit);
            jsonWriter.WriteEndObject();

            WebClient webClient = new WebClient();

            Console.WriteLine("[+] Going to download " + legacyIpcFiles.Count + " legacy IPC header files.");

            //
            // Download & analyse loop
            //
            List<IPCMessageStart> keys = legacyIpcFiles.Keys.ToList();
            for (int i = 0; i < keys.Count; i++)
            {
                IPCMessageStart messageStart = keys[i];
                string legacyIpcFilePath = legacyIpcFiles[messageStart];
                UInt32 messageClass = (UInt32)messageStart;

                if (legacyIpcFilePath == null) continue;

                Console.WriteLine("[+] Processing file " + legacyIpcFilePath);

                try
                {
                    string headerFileLink = "https://chromium.googlesource.com/chromium/src.git/+/" + commit + "/" + legacyIpcFilePath + "?format=text";
                    string headerFileContents = Encoding.Default.GetString(Convert.FromBase64String(webClient.DownloadString(headerFileLink)));

                    //
                    // Analyse this file
                    //
                    AnalyzeLegacyIpcHeaderFile(jsonWriter, messageClass, headerFileContents, legacyIpcFilePath, commit);

                }
                catch (WebException webException)
                {
                    if (((HttpWebResponse)webException.Response).StatusCode == (HttpStatusCode)429)
                    {
                        Console.WriteLine("[!] Sleeping 10 seconds to avoid Too Many Requests error.");
                        Thread.Sleep(10000);
                        i--;
                        continue;
                    }
                    if (((HttpWebResponse)webException.Response).StatusCode == HttpStatusCode.NotFound)
                    {
                        // this IPC header file was not found, most likely because it was removed in newer versions of chromium.
                        // just ignore
                        continue;
                    }

                    textWriter.Close();
                    File.Delete(CACHE_FILENAME);
                    throw webException;
                }
            }

            jsonWriter.WriteEndObject();
            textWriter.Close();
        }

        public static void AnalyzeLegacyIpcHeaderFile(JsonWriter jsonWriter, UInt32 messageClass, string headerFileContents, string headerFilePath, string commit)
        {
            RegexOptions regexOptions = RegexOptions.Compiled | RegexOptions.Multiline | RegexOptions.Singleline;

            //
            // Extract message definitions
            //
            Regex messagesRegex = new Regex(@"^IPC_\w*?MESSAGE_\w*\((\w+),?" + 
                                            @"(?:[^()]|(?<open>\()|(?<-open>\)))*(?(open)(?!))?" +  // match balanced '(' and ')'
                                            @"\)", regexOptions);
            MatchCollection messageDefintionMatches = messagesRegex.Matches(headerFileContents);

            foreach (Match messageMatch in messageDefintionMatches)
            {
                string messageDefinition = messageMatch.Groups[0].Value;
                string messageName = messageMatch.Groups[1].Value;
                UInt32 messageDefinitionLine = ToLineNumber(headerFileContents, messageMatch.Groups[0].Index);
                UInt32 messageDeclerationLineEnd = ToLineNumber(headerFileContents, messageMatch.Groups[0].Index + messageMatch.Groups[0].Length);

                messageDefinition = CleanUpDefinition(messageDefinition);

                // calculate message type
                // https://source.chromium.org/chromium/chromium/src/+/master:ipc/ipc_message_macros.h;l=304
                UInt32 messageType = (messageClass << 16) + messageDeclerationLineEnd;

                string headerFileLink = @"https://source.chromium.org/chromium/chromium/src/+/" + commit + ":" + headerFilePath + ";l=" + messageDefinitionLine;

                jsonWriter.WritePropertyName(messageType.ToString("X"));
                jsonWriter.WriteStartObject();
                jsonWriter.WritePropertyName("name");
                jsonWriter.WriteValue(messageName);
                jsonWriter.WritePropertyName("definition");
                jsonWriter.WriteValue(messageDefinition.Trim());
                jsonWriter.WritePropertyName("link");
                jsonWriter.WriteValue(headerFileLink);
                jsonWriter.WriteEndObject();
            }
        }

        public static uint ToLineNumber(string input, int indexPosition)
        {
            uint lineNumber = 1;
            for (int i = 0; i < indexPosition; i++)
            {
                if (input[i] == '\n') lineNumber++;
            }
            return lineNumber;
        }

        public static string CleanUpDefinition(string definition)
        {
            definition = string.Join("\n", definition.Split('\n').Select(line => line.Contains(@"//") ? line.Substring(0, line.IndexOf(@"//")) : line)); // remove trailing comments
            definition = string.Join("", definition.Split('\n').Where(line => line.Trim() != string.Empty)); // remove empty lines
            definition = definition.Replace("\\\"", "'"); // replace double quotes with single quote (to make sure lua will evaluate it)

            definition = new Regex("[ ]{2,}", RegexOptions.None).Replace(definition, " ");  // replace multiple spaces with one space
            definition = definition.Replace("\n", ""); // make everything one line

            return definition.Trim();
        }

        //
        // https://source.chromium.org/chromium/chromium/src/+/master:ipc/ipc_message_start.h;l=14
        //
        public enum IPCMessageStart
        {
            AutomationMsgStart = 0,
            FrameMsgStart,
            TestMsgStart,
            WorkerMsgStart,
            NaClMsgStart,
            GpuChannelMsgStart,
            MediaMsgStart,
            PpapiMsgStart,
            ChromeMsgStart,
            PrintMsgStart,
            ExtensionMsgStart,
            ChromotingMsgStart,
            AndroidWebViewMsgStart,
            NaClHostMsgStart,
            EncryptedMediaMsgStart,
            GinJavaBridgeMsgStart,
            ChromeUtilityPrintingMsgStart,
            ExtensionsGuestViewMsgStart,
            GuestViewMsgStart,
            MediaPlayerDelegateMsgStart,
            ExtensionWorkerMsgStart,
            SubresourceFilterMsgStart,
            UnfreezableFrameMsgStart,
            LastIPCMsgStart  // Must come last.
        };
    }
}
