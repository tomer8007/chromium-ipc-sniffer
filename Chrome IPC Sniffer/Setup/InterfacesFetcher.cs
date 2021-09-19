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

namespace ChromiumIPCSniffer.Mojo
{
    /// <summary>
    /// This class fetches Chrome's source code to get information about all the mojo interfaces that exist.
    /// It uses both GitHub API and chromium.googlesource.com
    /// </summary>
    public class InterfacesFetcher
    {
        public static string CACHE_FILENAME = @"Dissectors/helpers/mojo_interfaces.json";
        public static List<string> directoriesToLookIn = new List<string> { "services", "ui", "chrome", "media", "mojo", "url", "cc",
                                                                            "components", "content", "third_party", "device", "ipc", "gpu" };

        public static string[] ignoredFeatures = new string[] { "is_posix", "is_android", "is_chromeos", "is_fuchsia", "is_ios", "is_linux", "is_mac",
                                                                    "needs_crypt_config", "is_non_android_posix", "ipc_logging", "clang_profiling_inside_sandbox",
                                                                    "enable_offline_pages", "network_change_notifier_in_browser"};

        /// <summary>
        /// Downloads and analyses the .mojom files from the chromium git repository,
        /// in case a cache does not exist
        /// </summary>
        /// <param name="force"></param>
        /// <returns>The cached interfaces chromium version</returns>
        public static string UpdateInterfacesInfoIfNeeded(string chromeVersion, bool force = false)
        {
            if (!force)
            {
                Console.WriteLine("[+] Checking mojom interfaces information");
                if (File.Exists(CACHE_FILENAME))
                {
                    dynamic interfaceInfo = JsonConvert.DeserializeObject(File.ReadAllText(CACHE_FILENAME));
                    string cachedVersion = interfaceInfo["metadata"]["version"];
                    return cachedVersion;
                }
            }

            string commit = ChromeMonitor.GetCommitForVersion(chromeVersion);
            Console.WriteLine("[+] Matching commit is " + commit);

            List<string> mojoFilePaths = GetMojomFilesPaths(chromeVersion, commit);
            DownloadAndAnalyzeMojomFiles(mojoFilePaths, commit, chromeVersion);

            return chromeVersion;
        }

        /// <summary>
        /// Uses the GitHub API to get a list of all .mojom files in the chromium repository
        /// </summary>
        /// <param name="chromeVersion"></param>
        /// <param name="latestCommit"></param>
        /// <returns></returns>
        public static List<string> GetMojomFilesPaths(string chromeVersion, string latestCommit)
        {
            List<string> mojomFilesPaths = new List<string>();

            Console.WriteLine("[+] Fetching mojom files...");
            WebClient webClient = new WebClient();

            //
            // Iterate over all top-level directories
            //
            webClient.Headers.Add("User-Agent", "Chrome IPC Sniffer");
            dynamic directories = JsonConvert.DeserializeObject(webClient.DownloadString("https://api.github.com/repos/chromium/chromium/contents?ref=" + latestCommit));
            foreach (var directory in directories)
            {
                if (directory["type"] == "dir" && directoriesToLookIn.Contains((string)directory["name"]))
                {
                    //
                    // Get list of all files under this directory, recursively
                    //

                    string directoryListingUrl = directory["git_url"] + "?recursive=1";
                    string directoryName = directory["path"];

                    Console.WriteLine("[+] Downloading dir tree '{0}'", directoryName);

                    webClient.Headers.Add("User-Agent", "Chrome IPC Sniffer");
                    dynamic directoryListing = JsonConvert.DeserializeObject(webClient.DownloadString(directoryListingUrl));
                    dynamic filesList = directoryListing["tree"];
                    foreach (var file in filesList)
                    {
                        string filePath = directoryName + "/" + file["path"];
                        if (filePath.EndsWith(".mojom"))
                        {
                            mojomFilesPaths.Add(filePath);
                        }
                    }
                }
            }

            return mojomFilesPaths;
        }

        /// <summary>
        /// Iterates the given mojom file paths, downloads them, extracts interfaces/structs information,
        /// and writes the results to a file
        /// </summary>
        /// <param name="mojomFiles"></param>
        /// <param name="commit"></param>
        /// <param name="chromeVersion"></param>
        public static void DownloadAndAnalyzeMojomFiles(List<string> mojomFiles, string commit, string chromeVersion)
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

            Console.WriteLine("[+] Going to download " + mojomFiles.Count + " mojom files.");

            //
            // Download & analyse loop
            //
            for (int i = 0; i < mojomFiles.Count; i++)
            {
                string mojomFilePath = mojomFiles[i];
                Console.WriteLine("[+] " + i + ".Processing file " + mojomFilePath);

                try
                {
                    string mojomFileLink = "https://chromium.googlesource.com/chromium/src.git/+/" + commit + "/" + mojomFilePath + "?format=text";
                    string mojomFile = Encoding.Default.GetString(Convert.FromBase64String(webClient.DownloadString(mojomFileLink)));

                    //
                    // Analyse this file
                    //
                    AnalyzeMojomFile(jsonWriter, mojomFile, mojomFilePath, commit);

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

                    throw webException;
                }
            }

            //
            // Write special interfaces
            //
            jsonWriter.WritePropertyName("mojo.interface_control.Run");
            jsonWriter.WriteStartObject();
            jsonWriter.WritePropertyName("definition");
            jsonWriter.WriteValue("Run@0xFFFFFFFF(RunInput input) => (RunOutput? output)");
            jsonWriter.WritePropertyName("link");
            jsonWriter.WriteValue("https://source.chromium.org/chromium/chromium/src/+/master:mojo/public/interfaces/bindings/interface_control_messages.mojom;l=18");
            jsonWriter.WriteEndObject();
            jsonWriter.WritePropertyName("mojo.interface_control.RunOrClosePipe");
            jsonWriter.WriteStartObject();
            jsonWriter.WritePropertyName("definition");
            jsonWriter.WriteValue("RunOrClosePipe@0xFFFFFFFE(RunOrClosePipeInput input)");
            jsonWriter.WritePropertyName("link");
            jsonWriter.WriteValue("https://source.chromium.org/chromium/chromium/src/+/master:mojo/public/interfaces/bindings/interface_control_messages.mojom;l=48");
            jsonWriter.WriteEndObject();

            jsonWriter.WriteEndObject();
            textWriter.Close();
        }

        public static void AnalyzeMojomFile(JsonWriter jsonWriter, string mojomFileContents, string mojomFilePath, string commit)
        {
            RegexOptions regexOptions = RegexOptions.Compiled | RegexOptions.Multiline | RegexOptions.Singleline;
            Regex moduleRegex = new Regex(@"^module (.*?);", regexOptions);
            string moduleName = moduleRegex.Match(mojomFileContents).Groups[1].Value;

            //
            // Extract interfaces and methods
            //
            Regex interfacesRegex = new Regex(@"^interface (.*?) \{(" + 
                                                @"(?:[^{}]|(?<open>\{)|(?<-open>\}))*(?(open)(?!))" +   // match balanced '{' and '}'
                                                @")\};", regexOptions);
            MatchCollection interfacesMatches = interfacesRegex.Matches(mojomFileContents);

            foreach (Match interfaceMatch in interfacesMatches)
            {
                string interfaceDefinition = interfaceMatch.Groups[0].Value;
                string interfaceName = interfaceMatch.Groups[1].Value;
                int interfaceDefinitionLine = ToLineNumber(mojomFileContents, interfaceMatch.Groups[0].Index);

                // Iterate the methods defined in this interace
                Regex methodsRegex = new Regex(@"^[^\/{}]+?\(.*?\);", regexOptions);
                MatchCollection methodMatches = methodsRegex.Matches(interfaceDefinition);
                foreach (Match methodMatch in methodMatches)
                {
                    string methodDecleration = methodMatch.Groups[0].Value.Trim();
                    int methodDeclerationLine = interfaceDefinitionLine + ToLineNumber(interfaceDefinition, methodMatch.Groups[0].Index) - 1;
                    string methodName = methodDecleration.Trim().Split('(')[0].Replace("\n", "");

                    methodDecleration = CleanUpDefinition(methodDecleration);

                    // check for [EnableIf=SomeCondition] stuff
                    if (methodName.IndexOf(']') != -1)
                    {
                        // extract the real method name
                        methodName = methodName.Substring(methodName.IndexOf(']') + 1).Trim();

                        if (methodDecleration.Contains("EnableIf=") && !methodDecleration.Contains("EnableIf=is_win"))
                        {
                            // We are on Windows. skip anything that wouldn't have compiled on release versions
                            if (ignoredFeatures.Any(feature => methodDecleration.Contains("EnableIf=" + feature)))
                                continue;
                        }
                    }

                    string fullMethodName = moduleName + "." + interfaceName + "." + methodName;

                    string mojomFileLink = @"https://source.chromium.org/chromium/chromium/src/+/" + commit + ":" + mojomFilePath + ";l=" + methodDeclerationLine;

                    jsonWriter.WritePropertyName(fullMethodName);
                    jsonWriter.WriteStartObject();
                    jsonWriter.WritePropertyName("definition");
                    jsonWriter.WriteValue(methodDecleration.Trim());
                    jsonWriter.WritePropertyName("link");
                    jsonWriter.WriteValue(mojomFileLink);
                    jsonWriter.WriteEndObject();
                }
            }

            //
            // Extract structs, enums and unions
            //
            Regex structsRegex = new Regex(@"^ *struct (\w+?) \{((?:[^{}]|(?<open>\{)|(?<-open>\}))*(?(open)(?!)))\};|^ *struct (\w+?);", regexOptions);
            Regex enumsRegex = new Regex(@"^ *enum (\w+?) \{((?:[^{}]|(?<open>\{)|(?<-open>\}))*(?(open)(?!)))\};|^ *enum (\w+?);", regexOptions);
            Regex unionsRegex = new Regex(@"^ *union (\w+?) \{((?:[^{}]|(?<open>\{)|(?<-open>\}))*(?(open)(?!)))\};|^ *union (\w+?);", regexOptions);

            MatchCollection structsMatches = structsRegex.Matches(mojomFileContents);
            MatchCollection enumsMatches = enumsRegex.Matches(mojomFileContents);
            MatchCollection unionsMatches = unionsRegex.Matches(mojomFileContents);
            IEnumerable<Match> combinedMatches = structsMatches.OfType<Match>().Concat(enumsMatches.OfType<Match>()).Concat(unionsMatches.OfType<Match>()).Where(m => m.Success);

            foreach (Match match in combinedMatches)
            {
                string structDefinition = match.Groups[0].Value.Trim();
                string stuctName = match.Groups[1].Value != "" ? match.Groups[1].Value : structDefinition.Split(' ')[1].Replace(";", "");
                string fullStructName = moduleName + "." + stuctName;
                string structContents = match.Groups[2].Value;
                int structDefinitionLine = ToLineNumber(mojomFileContents, match.Groups[0].Index);

                if (structContents != "")
                {
                    // TODO: inner structs/enums should be extracted instead of cleaned
                    string structContentsCleaned = CleanUpInnerStructs(structContents, structsRegex, enumsRegex, unionsRegex);
                    structDefinition = structDefinition.Replace(structContents, structContentsCleaned);
                }

                structDefinition = CleanUpDefinition(structDefinition);

                string mojomFileLink = @"https://source.chromium.org/chromium/chromium/src/+/" + commit + ":" + mojomFilePath + ";l=" + structDefinitionLine;

                jsonWriter.WritePropertyName(fullStructName); jsonWriter.WriteStartObject();
                jsonWriter.WritePropertyName("definition");
                jsonWriter.WriteValue(structDefinition.Trim());
                jsonWriter.WritePropertyName("link");
                jsonWriter.WriteValue(mojomFileLink);
                jsonWriter.WriteEndObject();
            }

        }

        public static int ToLineNumber(string input, int indexPosition)
        {
            int lineNumber = 1;
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

        public static string CleanUpInnerStructs(string outerDefinition, params Regex[] regexToDelete)
        {
            foreach (Regex regex in regexToDelete)
            {
                MatchCollection matches = regex.Matches(outerDefinition);
                foreach (Match match in matches)
                {
                    string innerStructDefinition = match.Groups[0].Value;
                    outerDefinition = outerDefinition.Replace(innerStructDefinition, "");
                }
            }

            return outerDefinition;
        }
    }
}
