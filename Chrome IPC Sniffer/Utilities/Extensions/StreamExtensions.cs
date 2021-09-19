using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;

namespace ChromiumIPCSniffer
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

        /// <summary>
        /// Reads a struct, and then returns the position pointer
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static T PeekStruct<T>(this BinaryReader stream) where T : struct
        {
            T structure = stream.ReadStruct<T>();
            stream.BaseStream.Seek(-Marshal.SizeOf<T>(), SeekOrigin.Current);
            return structure;
        }

        public static string ReadCString(this BinaryReader reader, int maxLength = Int32.MaxValue)
        {
            List<char> chars = new List<char>();
            byte currentByte = 0;

            do
            {
                try
                {
                    currentByte = reader.ReadByte();
                    if (currentByte == 0)
                    {
                        reader.BaseStream.Seek(-1, SeekOrigin.Current);
                        break;
                    }

                    chars.Add((char)currentByte);

                    if (chars.Count > maxLength) return null;
                }
                catch (EndOfStreamException)
                {
                    return null;
                }
            }
            while (currentByte != 0);

            return new string(chars.ToArray());
        }

        /// <summary>
        /// Reads a C string, then returns the stream position
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static string PeekCString(this BinaryReader reader)
        {
            long position = reader.BaseStream.Position;
            string cString = reader.ReadCString();
            reader.BaseStream.Position = position;
            return cString;
        }

        /// <summary>
        /// Reads a byte, then returns the stream position
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static byte PeekByte(this BinaryReader reader)
        {
            long position = reader.BaseStream.Position;
            byte theByte = reader.ReadByte();
            reader.BaseStream.Position = position;
            return theByte;
        }

        public static int SkipPadding(this BinaryReader reader, int alignment = 16, byte[] paddingChars = null)
        {
            if (paddingChars == null) paddingChars = new byte[0];

            int missingPadding = (int)(alignment - ((reader.BaseStream.Position) % alignment));
            if (missingPadding == alignment && reader.PeekByte() != 0) missingPadding = 0;
            reader.ReadBytes(missingPadding);

            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                byte currentByte = reader.ReadByte();
                if (!paddingChars.Any(c => c == currentByte))
                {
                    reader.BaseStream.Position -= 1;
                    break;
                }
                missingPadding++;
            }


            return missingPadding;
        }

        public static int SkipPaddingBackwards(this BinaryReader reader, int alignment = 16, byte[] paddingChars = null)
        {
            if (paddingChars == null) paddingChars = new byte[0];

            int missingPadding = (int)((reader.BaseStream.Position) % alignment);
            reader.BaseStream.Position -= missingPadding;

            while (reader.BaseStream.Position < 0)
            {
                reader.BaseStream.Position -= 1;

                byte currentByte = reader.PeekByte();
                if (!paddingChars.Any(c => c == currentByte))
                {
                    reader.BaseStream.Position += 1;
                    break;
                }
                missingPadding++;
            }

            return missingPadding;
        }

        public static int SkipPaddingBackwards(this BinaryReader reader, params byte[] paddingChars)
        {
            int skippedPaddingCount = 0;
            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                byte currentByte = reader.ReadByte();
                if (!paddingChars.Any(c => c == currentByte)) break;
                skippedPaddingCount++;
            }

            return skippedPaddingCount;
        }

        public static int SkipZeroes(this BinaryReader reader, int maxDistance = 50)
        {
            for (int j = 0; j < maxDistance; j++)
            {
                byte c = reader.ReadByte();

                if (c != 0)
                {
                    reader.BaseStream.Position -= 1;
                    return j;
                }
            }

            return -1; // too many zeroes
        }

        public static int SkipZeroesBackwards(this BinaryReader reader, int maxDistance = 50)
        {
            for (int j = 0; j < maxDistance; j++)
            {
                reader.BaseStream.Position -= 1;

                byte c = reader.ReadByte();
                reader.BaseStream.Position -= 1;
                if (c != 0)
                {
                    return j;
                }
            }

            return -1; // too many zeroes backwards
        }

        public static int GoToStringBeggining(this BinaryReader reader, int maxDistance = 100)
        {
            for (int j = 0; j < maxDistance; j++)
            {
                reader.BaseStream.Seek(-1, SeekOrigin.Current);

                long position = reader.BaseStream.Position;
                byte c = reader.ReadByte();
                reader.BaseStream.Position = position;

                if (c == 0)
                {
                    reader.ReadByte();
                    return j;
                }
            }

            return -1; // too many zeroes backwards
        }
    }
}
