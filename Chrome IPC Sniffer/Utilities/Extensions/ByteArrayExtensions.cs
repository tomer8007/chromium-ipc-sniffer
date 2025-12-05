using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ChromiumIPCSniffer
{
    public static class ByteArrayExtensions
    {
        static readonly int[] Empty = new int[0];

        public static int[] Locate(this byte[] self, byte[] candidate, int maxResults = int.MaxValue)
        {
            if (IsEmptyLocate(self, candidate))
                return Empty;

            var list = new List<int>();

            for (int i = 0; i < self.Length; i++)
            {
                if (!IsMatch(self, i, candidate))
                    continue;

                list.Add(i);

                if (list.Count >= maxResults) return list.ToArray();
            }

            return list.Count == 0 ? Empty : list.ToArray();
        }

        public static int FindStringBeginning(this byte[] self, int index, int maxBackwards= 50)
        {
            for (int j = 0; j < maxBackwards; j++)
            {
                byte c = self[index - j];
                if (c >= 128 || Char.IsControl((char)c))
                {
                    return index - j + 1;
                }
            }

            return -1; // the string is too long backwards
        }

        public static int FindZeroesBeginning(this byte[] self, int index, int maxBackwards = 50)
        {
            for (int j = 0; j < maxBackwards; j++)
            {
                byte c = self[index - j];
                if (c != 0)
                {
                    return index - j + 1;
                }
            }

            return -1; // the string is too long backwards
        }

        static bool IsMatch(byte[] array, int position, byte[] candidate)
        {
            if (candidate.Length > (array.Length - position))
                return false;

            for (int i = 0; i < candidate.Length; i++)
                if (array[position + i] != candidate[i])
                    return false;

            return true;
        }

        static bool IsEmptyLocate(byte[] array, byte[] candidate)
        {
            return array == null
                || candidate == null
                || array.Length == 0
                || candidate.Length == 0
                || candidate.Length > array.Length;
        }
    }
}
