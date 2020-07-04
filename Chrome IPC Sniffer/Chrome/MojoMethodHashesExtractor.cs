using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace ChromeIPCSniffer
{
    public class MojoMethodHashesExtractor
    {
        public static string CACHE_FILENAME = @"Dissectors/helpers/mojo_interfaces_map.lua";

        /// <summary>
        /// Finds method message names (scrambled DWORDs) and associates them with an interface name, out of chrome.dll
        /// </summary>
        /// <param name="force">Set to true to scan the file even a cached result was found for it</param>
        public static void ExtractMethodNames(string chromeDllPath, bool force = false)
        {
            Console.WriteLine("[+] Extracting scrambled message IDs from chrome.dll...");

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
        /// We do it this way since we can't really know the sault used in mojom_bindings_generator.py for official builds
        /// https://source.chromium.org/chromium/chromium/src/+/master:mojo/public/tools/bindings/mojom_bindings_generator.py;l=116
        /// </summary>
        private static void ExtractMeethodNamesInternal(string chromeDllPath, bool force = false)
        {
            byte[] chromeDll = File.ReadAllBytes(chromeDllPath);
            string chromeDllSha1 = string.Concat(new SHA1Managed().ComputeHash(chromeDll).Select(b => b.ToString("x2")));

            // check the cache
            if (File.Exists(CACHE_FILENAME) && !force)
            {
                string text = File.ReadAllText(CACHE_FILENAME);
                if (text.Contains(chromeDllSha1)) return;
            }

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

                int maxDistance = i + 1 < interestingOffsets.Length ? Math.Min(interestingOffsets[i + 1] - currentOffset, 4000) : 4000;
                BinaryReader reader = new BinaryReader(new MemoryStream(chromeDll, interfaceNameOffset, maxDistance));

                string interfaceName = "";
                interfaceName = reader.ReadCString();
                if (interfaceName == null || interfaceName.Length > 80 || interfaceName.Contains("/") || interfaceName.Contains(" ")) continue;

                // skip missing padding
                int missingPadding = (interfaceNameOffset + interfaceName.Length) % 8;
                if (missingPadding > 0) reader.ReadBytes(8 - missingPadding);

                // read the names; we may need to skip a vtable first
                List<UInt32> names = new List<UInt32>();
                while (reader.BaseStream.Length - reader.BaseStream.Position >= 8)
                {
                    UInt32 maybeName = reader.ReadUInt32();
                    UInt32 maybeNull = reader.ReadUInt32();

                    if (maybeNull == 0 && maybeName != 0 && maybeName > 1000000)
                    {
                        names.Add(maybeName);
                        // TODO: keep reading it in distances of 24 bytes
                    }
                }

                encounteredInterfaces.Add(interfaceName);

                if (names.Count > 0)
                {
                    List<string> methodNames = GetInterfaceMethods(interfaceName);

                    for (int j = 0; j < names.Count; j++)
                    {
                        UInt32 name = names[j];
                        string methodName = methodNames.Count > j ? methodNames[j] : j.ToString();

                        fileWriter.WriteLine("[\"n" + name.ToString("x") + "\"] = \"" + interfaceName + "." + methodName + "\", ");
                    }

                    resolvedInterfaces.Add(interfaceName);
                }
                else
                {
                    // we did not find any scrumbled method names.
                    // either something got wrong with parsing or this is a non-scrumbled interface (scramble_message_ids = false)
                    // https://source.chromium.org/chromium/chromium/src/+/master:out/win-Debug/gen/third_party/blink/public/mojom/appcache/appcache.mojom.cc;l=1794
                    // https://source.chromium.org/chromium/chromium/src/+/master:third_party/blink/public/mojom/BUILD.gn;l=301
                }
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
                    string methodName = methodNames.Count > j ? methodNames[j] : j.ToString();

                    fileWriter.WriteLine("[\"unscrumbled_" + j.ToString("x") + "\"] = \"" + interfaceName + "." + methodName + "\", ");
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
        public static List<string> GetInterfaceMethods(string interfaceName)
        {
            List<string> methodNames = new List<string>();
            if (File.Exists(MojoInterfacesFetcher.CACHE_FILENAME))
            {
                string fullMethodNames = File.ReadAllText(MojoInterfacesFetcher.CACHE_FILENAME);
                Regex interfacesRegex = new Regex("\\\"" + interfaceName + "\\.(.*?)\\\"", RegexOptions.Compiled | RegexOptions.Multiline | RegexOptions.Singleline);
                foreach (Match match in interfacesRegex.Matches(fullMethodNames))
                {
                    string fullMethodName = match.Groups[1].Value.Trim();
                    methodNames.Add(fullMethodName);
                }
            }

            return methodNames;
        }
    }
}
