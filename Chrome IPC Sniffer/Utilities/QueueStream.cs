using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ChromeIPCSniffer
{
    public class QueueStream : MemoryStream
    {
        public ManualResetEvent OnDataAvailable = new ManualResetEvent(false);

        public long ReadPosition = 0;
        public long WritePosition = 0;

        public QueueStream() : base() { }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public override int Read(byte[] buffer, int offset, int count)
        {
            Position = ReadPosition;
            //Console.WriteLine("Reading " + count + " bytes.");

            int readCount = base.Read(buffer, offset, count);

            ReadPosition = Position;

            if (ReadPosition == base.Length)
            {
                OnDataAvailable.Reset();
            }

            return readCount;
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public override void Write(byte[] buffer, int offset, int count)
        {
            Position = WritePosition;
            //Console.WriteLine("Writing " + count + " bytes.");

            base.Write(buffer, offset, count);

            WritePosition = Position;

            OnDataAvailable.Set();
        }
    }
}
