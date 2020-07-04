/**************************************************************************
*                           MIT License
* 
* Copyright (C) 2015 Frederic Chaxel <fchaxel@free.fr>
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*********************************************************************/
using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;
using System.IO.Pipes;
using System.Threading;
using System.Linq;
using System.Text;
//
// object creation could be done with 
//      var ws=new Wireshark.WiresharkSender("bacnet",165);  // pipe name is \\.\pipe\bacnet
//
// data to wireshark could be sent with something like that
//      if (ws.isConnected)
//          ws.SendToWireshark(new byte[]{0x55,0xFF,0,5,6,0,0,4}, 0, 8);
//
// Wireshark can be launch with : Wireshark -ni \\.\pipe\bacnet
//
// ... enjoy
//
namespace Wireshark
{
    // Pcap Global Header
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct pcap_hdr_g
    {
        UInt32 magic_number;   /* magic number */
        UInt16 version_major;  /* major version number */
        UInt16 version_minor;  /* minor version number */
        Int32 thiszone;       /* GMT to local correction */
        UInt32 sigfigs;        /* accuracy of timestamps */
        UInt32 snaplen;        /* max length of captured packets, in octets */
        UInt32 network;        /* data link type */

        public pcap_hdr_g(UInt32 snaplen, UInt32 network)
        {
            magic_number = 0xa1b2c3d4;
            version_major = 2;
            version_minor = 4;
            thiszone = 0;
            sigfigs = 0;
            this.snaplen = snaplen;
            this.network = network;
        }

        // struct Marshaling
        // Maybe a 'manual' byte by byte serialization could be required on some systems
        // work well on Win32, Win64 .NET 3.0 to 4.5
        public byte[] ToByteArray()
        {
            int rawsize = Marshal.SizeOf(this);
            byte[] rawdatas = new byte[rawsize];
            GCHandle handle = GCHandle.Alloc(rawdatas, GCHandleType.Pinned);
            IntPtr buffer = handle.AddrOfPinnedObject();
            Marshal.StructureToPtr(this, buffer, false);
            handle.Free();
            return rawdatas;
        }
    }

    // Pcap Packet Header
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct pcap_hdr_p
    {
        UInt32 ts_sec;         /* timestamp seconds */
        UInt32 ts_usec;        /* timestamp microseconds */
        UInt32 incl_len;       /* number of octets of packet saved in file */
        UInt32 orig_len;       /* actual length of packet */

        public pcap_hdr_p(UInt32 lenght, UInt32 datetime, UInt32 microsecond)
        {
            incl_len = orig_len = lenght;
            ts_sec = datetime;
            ts_usec = microsecond;
        }

        // struct Marshaling
        // Maybe a 'manual' byte by byte serialise could be required on some system
        public byte[] ToByteArray()
        {
            int rawsize = Marshal.SizeOf(this);
            byte[] rawdatas = new byte[rawsize];
            GCHandle handle = GCHandle.Alloc(rawdatas, GCHandleType.Pinned);
            IntPtr buffer = handle.AddrOfPinnedObject();
            Marshal.StructureToPtr(this, buffer, false);
            handle.Free();
            return rawdatas;
        }
    }

    public class WiresharkSender
    {
        NamedPipeServerStream WiresharkPipe;

        bool IsConnected = false;

        public string PipeName;
        UInt32 PcapNetID;

        object verrou = new object();

        public WiresharkSender(string pipe_name, UInt32 pcap_netid)
        {
            this.PipeName = pipe_name;
            this.PcapNetID = pcap_netid;

            // Open the pipe and wait to Wireshark on a background thread
            Thread th = new Thread(PipeCreate);
            th.IsBackground = true;
            th.Start();
        }

        private void PipeCreate()
        {
            try
            {
                WiresharkPipe = new NamedPipeServerStream(PipeName, PipeDirection.Out, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            }
            catch (IOException)
            {
                Console.WriteLine("[-] Got an IOException while trying to create the output pipe (Is there another sniffer running?).");
                Environment.Exit(1);
            }

            // Wait
            WiresharkPipe.WaitForConnection();

            // Wireshark Global Header
            pcap_hdr_g p = new pcap_hdr_g(65535, PcapNetID);
            byte[] bh = p.ToByteArray();
            WiresharkPipe.Write(bh, 0, bh.Length);

            IsConnected = true;
        }

        public bool isConnected
        {
            get { return IsConnected; }
        }

        private UInt32 DateTimeToUnixTimestamp(DateTime dateTime)
        {
            return (UInt32)(dateTime - new DateTime(1970, 1, 1).ToLocalTime()).TotalSeconds;
        }

        public bool SendToWiresharkAsEthernet(byte[] buffer, int offset)
        {
            byte[] arpHeader = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x07 };
            buffer = arpHeader.Concat(buffer).ToArray();

            return SendToWireshark(buffer, offset, buffer.Length, DateTime.Now);
        }

        public bool SendToWireshark(byte[] buffer, int offset)
        {
            return SendToWireshark(buffer, offset, buffer.Length, DateTime.Now);
        }

        public bool SendToWireshark(byte[] buffer, int offset, int lenght, DateTime date)
        {
            UInt32 date_sec, date_usec;

            // Suppress all values for ms, us and ns
            DateTime d2 = new DateTime((date.Ticks / (long)10000000) * (long)10000000);

            date_sec = DateTimeToUnixTimestamp(date);
            date_usec = (UInt32)((date.Ticks - d2.Ticks) / 10);

            return SendToWireshark(buffer, offset, lenght, date_sec, date_usec);
        }

        public bool SendToWireshark(byte[] buffer, int offset, int lenght, UInt32 date_sec, UInt32 date_usec)
        {
            if (IsConnected == false)
                return false;

            if (buffer == null) return false;
            if (buffer.Length < (offset + lenght)) return false;

            pcap_hdr_p pHdr = new pcap_hdr_p((UInt32)lenght, date_sec, date_usec);
            byte[] b = pHdr.ToByteArray();

            try
            {
                // Wireshark Header
                WiresharkPipe.Write(b, 0, b.Length);
                // Bacnet packet
                WiresharkPipe.Write(buffer, offset, lenght);
            }
            catch (System.IO.IOException)
            {
                // broken pipe, try to restart
                IsConnected = false;
                WiresharkPipe.Close();
                WiresharkPipe.Dispose();
                Thread th = new Thread(PipeCreate);
                th.IsBackground = true;
                th.Start();
                return false;
            }
            catch (Exception)
            {
                // Unknow error, not due to the pipe
                // No need to restart it
                return false;
            }

            return true;
        }

    }
}