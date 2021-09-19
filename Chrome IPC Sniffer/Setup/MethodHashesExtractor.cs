using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using ChromiumIPCSniffer.Mojo;
using static ChromiumIPCSniffer.Mojo.InernalStructs;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using System.Diagnostics;

namespace ChromiumIPCSniffer.Mojo
{
    public class MethodHashesExtractor
    {
        public static string CACHE_FILENAME = @"Dissectors/helpers/mojo_interfaces_map.lua";
        public static Dictionary<string, Tuple<List<string>, int>> methodsPerInterface = null;

        /// <summary>
        /// Finds method message names (scrambled DWORDs) and associates them with an interface name, out of chrome.dll
        /// </summary>
        /// <param name="force">Set to true to scan the file even a cached result was found for it</param>
        public static void ExtractMethodNames(string chromeDllPath, bool force = false)
        {
            Console.WriteLine("[+] Extracting scrambled message names from chrome.dll...");

            ExtractMeethodNamesInternal(chromeDllPath, force);
            GC.Collect();   // kick chrome.dll out of our process' private bytes
        }

        /// <summary>
        /// We extract method message names by scanning chrome.dll for interface names. 
        /// Then it is assumed that names-validators pairs will be followed in memory in some delta
        /// Example: NetworkContextClient::Name_[]
        ///     https://source.chromium.org/chromium/chromium/src/+/82edd58b07670dfe2cf84735680549799f511fd9:out/win-Debug/gen/services/network/public/mojom/network_context.mojom.cc;l=2445
        ///     is followed by kNetworkContextValidationInfo at
        ///     https://source.chromium.org/chromium/chromium/src/+/82edd58b07670dfe2cf84735680549799f511fd9:out/win-Debug/gen/services/network/public/mojom/network_context.mojom.cc;l=15260
        /// 
        /// We do it this way since we can't really know the salt used in mojom_bindings_generator.py for official builds
        /// https://source.chromium.org/chromium/chromium/src/+/master:mojo/public/tools/bindings/mojom_bindings_generator.py;l=123
        /// </summary>
        private static void ExtractMeethodNamesInternal(string chromeDllPath, bool force = false)
        {
            string chromeDllSha1 = ComputeSHA1OnFile(chromeDllPath);

            BinaryReader reader = new BinaryReader(new FileStream(chromeDllPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096 * 4));

            // check the cache before starting
            if (File.Exists(CACHE_FILENAME) && !force)
            {
                string text = File.ReadAllText(CACHE_FILENAME);
                if (text.Contains(chromeDllSha1)) return;
            }

            if (!File.Exists(InterfacesFetcher.CACHE_FILENAME))
            {
                Console.WriteLine("[-] Interface information does not exist, terminating.");
                return;
            }

            BuildInterfacesList();

            byte[] chromeDll = File.ReadAllBytes(chromeDllPath);
            int[] interestingOffsets = chromeDll.Locate(Encoding.Default.GetBytes(".mojom."));

            HashSet<string> encounteredInterfaces = new HashSet<string>();
            HashSet<string> resolvedInterfaces = new HashSet<string>();

            TextWriter fileWriter = new StreamWriter(CACHE_FILENAME, false);
            fileWriter.WriteLine("-- method names map for chrome.dll " + chromeDllSha1); fileWriter.WriteLine();
            fileWriter.WriteLine("local interfacesMap = {");

            for (int i = 0; i < interestingOffsets.Length; i++)
            {
                int currentOffset = interestingOffsets[i];

                int interfaceNameOffset = chromeDll.FindStringBeginning(currentOffset);
                if (interfaceNameOffset == -1) continue;

                reader.BaseStream.Position = interfaceNameOffset;

                string interfaceName = reader.ReadCString(maxLength: 80);
                if (interfaceName == null || interfaceName.Contains("/") || interfaceName.Contains(" ")) continue;

                reader.BaseStream.Position = interfaceNameOffset;
                ValidationTableEntry[] validationEntries = FindValidationInfoForInterfaceName(reader);

                // read the names
                List<UInt32> names = new List<UInt32>();
                foreach (ValidationTableEntry entry in validationEntries)
                {
                    names.Add((UInt32)entry.name);
                }

                encounteredInterfaces.Add(interfaceName);

                if (names.Count == 0)
                {
                    // we did not find any scrambled method names.
                    // either something got wrong with parsing or this is a non-scrumbled interface (scramble_message_ids = false)
                    continue;
                }

                List<string> methodNames = GetInterfaceMethods(interfaceName);

                for (int j = 0; j < methodNames.Count; j++)
                {
                    bool isKnown = j < names.Count;

                    string keyName = isKnown ? "n" + names[j].ToString("x") : "not_found";
                    string methodName = methodNames[j];

                    fileWriter.WriteLine("[\"" + keyName + "\"] = \"" + methodName + "\", ");
                }

                resolvedInterfaces.Add(interfaceName);

            }

            //
            // take care of failed interfaces
            //
            List<string> failedInterfaces = encounteredInterfaces.Where(interfaceName => !resolvedInterfaces.Contains(interfaceName)).ToList();
            foreach (string interfaceName in failedInterfaces)
            {
                List<string> methodNames = GetInterfaceMethods(interfaceName);

                for (int j = 0; j < methodNames.Count; j++)
                {
                    string keyName = "not_found";
                    string methodName = methodNames.Count > j ? methodNames[j] : j.ToString();

                    if (methodNames[j].Contains("@")) keyName = "unscrambled_" + j.ToString("x");

                    fileWriter.WriteLine("[\"" + keyName + "\"] = \"" + methodName + "\", ");
                }
            }

            //
            // write special message names
            //
            fileWriter.WriteLine("[\"n" + "ffffffff" + "\"] = \"" + "mojo.interface_control.Run" + "\", ");
            fileWriter.WriteLine("[\"n" + "fffffffe" + "\"] = \"" + "mojo.interface_control.RunOrClosePipe" + "\", ");


            fileWriter.WriteLine("};");
            fileWriter.WriteLine("return interfacesMap;");
            fileWriter.Close();
        }

        /// <summary>
        /// Returns a list of method names for a given interface, based on mojo_interfaces.json (which was created earlier)
        /// </summary>
        /// <param name="interfaceName">The interface name for which method names will be returned</param>
        /// <returns></returns>
        public static List<string> GetInterfaceMethods(params string[] interfaceNames)
        {
            List<string> foundMethodNames = new List<string>();


            // TODO: we need to return the methods in the same ORDER they appear in methodsPerInterface.
            // this means we need to use OrderedDictionary or so
            Array.Sort(interfaceNames, (name1, name2) => methodsPerInterface.ContainsKey(name1) && methodsPerInterface.ContainsKey(name2) ?
                                                            methodsPerInterface[name1].Item2 - methodsPerInterface[name2].Item2
                                                            : 0);
            foreach (string interfaceName in interfaceNames)
            {
                if (methodsPerInterface.ContainsKey(interfaceName))
                    foundMethodNames.AddRange(methodsPerInterface[interfaceName].Item1);
            }

            return foundMethodNames;
        }

        public static HashSet<Tuple<int, int>> succ = new HashSet<Tuple<int, int>>();

        // TODO TODO TODO TODO
        /// <summary>
        /// Tries to find the std::pair<uint32_t, mojo::internal::GenericValidationInfo> that corrosponds to the given ::Name_ (see explanation above).
        /// This is not so easy to do since recent chrome versions, but we're trying to make some guesses
        /// </summary>
        /// <param name="reader">A BinaryReader that its position is the interface's ::Name_</param>
        /// <returns></returns>
        public static ValidationTableEntry[] FindValidationInfoForInterfaceName(BinaryReader reader)
        {
            long interfaceNameOffset = reader.BaseStream.Position;

            string interfaceName = reader.ReadCString();
            List<string> expectedMethods = GetInterfaceMethods(interfaceName);
            reader.SkipPadding(16, new byte[] { 0xAA, 0xFF });

            List<ValidationTableEntry> possibleTable = ReadValidationTable(reader);
            if (possibleTable.Count == expectedMethods.Count)
            {
                // this looks like the naive case, so we will just go with this belief
                return possibleTable.ToArray();
            }

            // now things will get more complicated
            Tuple<int, int>[] attempts = { Tuple.Create(8, 12), Tuple.Create(2, 5), Tuple.Create(1, 5), Tuple.Create(1, 11),
                                            Tuple.Create(4, 8), Tuple.Create(2, 6)};
            foreach (Tuple<int, int> attempt in attempts)
            {
                int maxInterfacesBack = attempt.Item1;
                int maxInterfacesForward = attempt.Item2;

                reader.BaseStream.Position = interfaceNameOffset;

                GoBackXInterfaces(reader, maxInterfaces: maxInterfacesBack);
                (List<string> interfacesNames, List<ValidationTableEntry> validationEntries) = ReadInterfaces(reader, maxInterfaces: maxInterfacesForward);
                if (!interfacesNames.Contains(interfaceName)) continue;

                List<string> methods = GetInterfaceMethods(interfacesNames.ToArray());
                if (methods.Count > 0 && methods.Count == validationEntries.Count)
                {
                    // looks like we guessed right

                    //Console.WriteLine("Saved " + interfaceName);
                    succ.Add(attempt);
                    for (int i = 0; i < validationEntries.Count; i++)
                    {
                        if (methods[i].StartsWith(interfaceName + "."))
                            return validationEntries.Skip(i).ToArray();
                    }
                }
            }


            // something is not just right.
            // TODO #1: many times the issue is that the validation table for the non ::blink:: varaint is missing.
            //          for example, WebTransportClient/P2PNetworkNotificationClient/P2PSocketClient/RemoteFrame/RemoteMainFrame
            //          all do not have a validation table for their non-blink version
            //          sometimes the interface is missing the table for some other reason, for example in MdnsListenClient and NetworkServiceTest
            //          this is BY FAR the biggest problem here
            // TODO #2: we can't assume that interfaces defined in different files will in the same order we get them from server.
            //          example: ChunkedDataPipeGetter is after RestrictedCookieManager in memory, but not our in json array
            //          other example: WebSocketClient and AudioLog
            // TODO #3: maybe we can ignore interfaces whose validation table is placed in a "naive" way after them.
            //          validation tables can still be defined after these borders, for example in ResolveHostClient

            // maybe this interface has no methods or whatever. there are weird cases, and we're not gonna handle them all.
            // Console.WriteLine("Can't find " + interfaceName);

            return new ValidationTableEntry[0];

        }

        public static List<ValidationTableEntry> ReadValidationTable(BinaryReader reader, bool stopAtPadding = true)
        {
            List<ValidationTableEntry> validationEntries = new List<ValidationTableEntry>();
            ValidationTableEntry validationEntry;

            int validationEntrySize = Marshal.SizeOf<ValidationTableEntry>();
            long lastGoodPosition = reader.BaseStream.Position;

            do
            {
                validationEntry = reader.ReadStruct<ValidationTableEntry>();

                if (validationEntry.LooksCorrect())
                {
                    validationEntries.Add(validationEntry);
                    lastGoodPosition = reader.BaseStream.Position;
                }
                else if (validationEntry.requestValidator > 0x4000 && validationEntry.requestValidator < UInt32.MaxValue)
                {
                    // maybe this is just a padding. try to skip it

                    if (stopAtPadding) break;
                    reader.BaseStream.Position -= validationEntrySize;
                    reader.BaseStream.Position += 8;
                    validationEntry = reader.PeekStruct<ValidationTableEntry>();
                }

            } while (validationEntry.LooksCorrect());
            reader.BaseStream.Position = lastGoodPosition; // account for last unsuccessful read

            return validationEntries;
        }

        public static void GoBackXInterfaces(BinaryReader reader, long maxInterfaces = 5)
        {
            List<string> interfacesNames = new List<string>();

            int validationEntrySize = Marshal.SizeOf<ValidationTableEntry>();

            reader.SkipPaddingBackwards();

            int distancePassed = 0;
            const int maxDistance = 5000;

            long lastGoodPosition = reader.BaseStream.Position;

            while (distancePassed < maxDistance && interfacesNames.Count < maxInterfaces)
            {
                reader.BaseStream.Position -= 16;
                distancePassed += 16;

                string maybeInterfaceName = reader.PeekCString();

                if (maybeInterfaceName.Contains(".mojom."))
                {
                    interfacesNames.Add(maybeInterfaceName);
                    lastGoodPosition = reader.BaseStream.Position;
                }

            }
            reader.BaseStream.Position = lastGoodPosition; // account for last unsuccessful read
        }

        public static (List<string>, List<ValidationTableEntry>) ReadInterfaces(BinaryReader reader, int maxInterfaces = 5)
        {
            List<string> interfacesNames = new List<string>();
            List<ValidationTableEntry> validationEntries = new List<ValidationTableEntry>();

            long lastGoodPosition = reader.BaseStream.Position;
            long originalPosition = reader.BaseStream.Position;

            const int maxDistance = 6000;

            while (reader.BaseStream.Position - originalPosition < maxDistance && interfacesNames.Count < maxInterfaces)
            {

                reader.SkipPadding();
                string maybeInterfaceName = reader.PeekCString();

                if (maybeInterfaceName.Contains(".mojom."))
                {
                    interfacesNames.Add(maybeInterfaceName);

                    reader.BaseStream.Position += maybeInterfaceName.Length;
                    reader.BaseStream.Position += reader.SkipPadding();
                }
                else
                {
                    reader.BaseStream.Position += 16;
                }

                List<ValidationTableEntry> entries = ReadValidationTable(reader, stopAtPadding: false);
                if (entries.Count > 0)
                {
                    validationEntries.AddRange(entries);
                    lastGoodPosition = reader.BaseStream.Position;
                }

            }

            reader.BaseStream.Position = lastGoodPosition;

            return (interfacesNames, validationEntries);
        }

        public static void BuildInterfacesList()
        {
            methodsPerInterface = new Dictionary<string, Tuple<List<string>, int>>();

            string cacheFileContents = File.ReadAllText(InterfacesFetcher.CACHE_FILENAME);
            Dictionary<string, object> methodsList = JsonConvert.DeserializeObject<Dictionary<string, object>>(cacheFileContents);
            string[] knownMethodsList = methodsList.Keys.ToArray();
            for (int i = 0; i < knownMethodsList.Length; i++)
            {
                string method = knownMethodsList[i];

                if (method.LastIndexOf(".") == -1) continue;
                string interfaceName = method.Substring(0, method.LastIndexOf("."));

                if (!methodsPerInterface.ContainsKey(interfaceName))
                {
                    methodsPerInterface[interfaceName] = Tuple.Create(new List<string>(), i);
                }

                methodsPerInterface[interfaceName].Item1.Add(method);
            }
        }

        public static string ComputeSHA1OnFile(string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096 * 4))
            using (BufferedStream bs = new BufferedStream(fs))
            {
                using (SHA1Managed sha1 = new SHA1Managed())
                {
                    byte[] hash = sha1.ComputeHash(bs);
                    StringBuilder formatted = new StringBuilder(2 * hash.Length);
                    foreach (byte b in hash)
                    {
                        formatted.AppendFormat("{0:x2}", b);
                    }

                    return formatted.ToString();
                }
            }
        }
    }
}
