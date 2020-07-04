using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;

namespace ChromeIPCSniffer
{
    public static class StreamExtensions
    {
        public static T ReadStruct<T>(this BinaryReader stream) where T : struct
        {
            var sz = Marshal.SizeOf(typeof(T));
            var buffer = new byte[sz];
            int read = stream.Read(buffer, 0, sz);
            if (read != sz)
            {
                throw new Exception("Could not read entire struct! read " + read + " out of " + sz + " bytes");
            }
            var pinnedBuffer = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            var structure = (T)Marshal.PtrToStructure(
                pinnedBuffer.AddrOfPinnedObject(), typeof(T));
            pinnedBuffer.Free();
            return structure;
        }

        public static string ReadCString(this BinaryReader reader)
        {
            List<char> chars = new List<char>();
            while (reader.PeekChar() != 0)
            {
                try
                {
                    chars.Add(reader.ReadChar());
                }
                catch (EndOfStreamException)
                {
                    return null;
                }
            }

            return new string(chars.ToArray());
        }
    }
}
