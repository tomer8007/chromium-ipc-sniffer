using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Security.Principal;
using System.Reflection;
using Wireshark;
using System.Runtime.InteropServices;
using System.Collections;
using System.Linq;

using static ChromeIPCSniffer.TDevMonitor;

namespace ChromeIPCSniffer
{
    class NamedPipeSniffer
    {
        private WiresharkSender wiresharkSender;
        private ChromeMonitor chromeMonitor;

        string pipeNameFilter = "";
        private bool recordingOnlyNewMojoPipes;

        // Tibbo Device Monitor buffering
        private TDevMonitor tdevMonitor;
        private int BLOCK_SIZE = 4096;
        private StreamReader tdevStream;
        private bool useExtraStreamBuffering = false;
        private QueueStream tdevBufferedStream;
        private bool isShuttingDown = false;

        // simulated stream (for debugging)
        private bool useSimulatedStream = false;
        private bool recordStream = false;
        private StreamWriter replayStreamWriter;

        // statistics
        private int numPacketsProcessed = 0;
        private DateTime lastDropTime;

        Dictionary<string, NamedPipeInfo> namedPipeFiles;
        List<string> destoryedNamedPipes;

        public NamedPipeSniffer(ChromeMonitor chromeMonitor, string wiresharkPipeName, string nameFilter = "", bool recordOnlyNewMojoPipes = false)
        {
            this.wiresharkSender = new WiresharkSender(wiresharkPipeName, 1);
            this.namedPipeFiles = new Dictionary<string, NamedPipeInfo>();
            this.destoryedNamedPipes = new List<string>();
            this.chromeMonitor = chromeMonitor;
            this.recordingOnlyNewMojoPipes = recordOnlyNewMojoPipes;
            this.pipeNameFilter = nameFilter;
            this.lastDropTime = DateTime.Now;
            this.numPacketsProcessed = 0;
        }

        /// <summary>
        /// Starts the pipe monitoring capability using Tibbo driver,
        /// as well as the processing/consuming loop
        /// </summary>
        /// <returns></returns>
        public bool Start()
        {
            bool isElevated = ElevationUtils.HasAdminRights();
            if (!isElevated)
            {
                Console.WriteLine("[-] Admin privileges is needed to use the sniffing driver.");
                return false;
            }

            this.tdevMonitor = new TDevMonitor();

            if (useSimulatedStream)
            {
                Console.WriteLine("[+] Re-playing previously recorded packets stream.");
                this.tdevStream = new StreamReader(new FileStream(@"last_tdevmon_stream.bin", FileMode.Open));
            }
            else
            {
                this.tdevStream = this.tdevMonitor.StartMonitoringDevice(@"\Device\NamedPipe", this.recordingOnlyNewMojoPipes ? "*mojo*" : "");
            }

            if (recordStream)
            {
                replayStreamWriter = new StreamWriter(new FileStream("last_tdevmon_stream.bin", FileMode.Create));
            }

            if (useExtraStreamBuffering)
            {
                this.tdevBufferedStream = new QueueStream();
                Thread readingLoopThread = new Thread(new ThreadStart(ExtraBufferingReadingLoop));
                readingLoopThread.Start();
            }

            Thread processingLoopThread = new Thread(new ThreadStart(ProcessingLoop));
            processingLoopThread.Priority = ThreadPriority.AboveNormal;
            processingLoopThread.Start();

            Thread statisticsThread = new Thread(new ThreadStart(StatisticsThread));
            statisticsThread.Start();

            return true;
        }

        private void StatisticsThread()
        {
            Thread.Sleep(1000);

            var startTimeSpan = TimeSpan.Zero;
            var periodTimeSpan = TimeSpan.FromSeconds(0.3);

            while (!isShuttingDown)
            {
                Thread.Sleep((int)periodTimeSpan.TotalMilliseconds);
                int packetsPerSecond = (int)((double)this.numPacketsProcessed / periodTimeSpan.TotalSeconds);

                Console.SetCursorPosition(0, Console.CursorTop - 1);
                Console.WriteLine("[+] Capturing " + packetsPerSecond + " packets/second...");

                this.numPacketsProcessed = 0;
            }
        }

        /// <summary>
        /// Continiously reads notification data from the kernel driver/buffering stream
        /// and heads it over to ProcessNotification
        /// </summary>
        public void ProcessingLoop()
        {
            BinaryReader sourceTdevStream = useExtraStreamBuffering ? new BinaryReader(this.tdevBufferedStream) :
                                                                   new BinaryReader(this.tdevStream.BaseStream);

            Stopwatch totalStopwatch = new Stopwatch();
            totalStopwatch.Start();

            long streamPosition = 0;
            double timePeek = 0;

            BinaryReader packetsReader;

            while (!isShuttingDown)
            {
                if (this.tdevBufferedStream != null) this.tdevBufferedStream.OnDataAvailable.WaitOne();

                // Read the next bunch of packets
                packetsReader = new BinaryReader(new MemoryStream());
                AppendToStream(sourceTdevStream.BaseStream, packetsReader.BaseStream, BLOCK_SIZE);

                Stopwatch sw = new Stopwatch();
                sw.Start();

                while (packetsReader.BaseStream.Position < packetsReader.BaseStream.Length)
                {
                    long headerEndOffset = packetsReader.BaseStream.Position + Marshal.SizeOf(typeof(dm_NotifyHdr));
                    if (packetsReader.BaseStream.Length < headerEndOffset &&
                        tdevMonitor.ReadMode == dm_ReadMode.dm_ReadMode_Stream)
                    {
                        // We need to read more data so the notification header could be read completely
                        long missingSize = headerEndOffset - packetsReader.BaseStream.Length;
                        AppendToStream(sourceTdevStream.BaseStream, packetsReader.BaseStream, missingSize, true);
                    }

                    dm_NotifyHdr notificationHeader = packetsReader.ReadStruct<dm_NotifyHdr>();
                    if (notificationHeader.signature != 1852796276)
                    {
                        throw new Exception("Encountered bad signature (" + notificationHeader.signature + ") at position "
                            + (streamPosition + packetsReader.BaseStream.Position) + "!");
                    }

                    long notificationParamBeginOffset = packetsReader.BaseStream.Position;

                    if ((notificationHeader.flags & (ushort)dm_NotifyFlag.dm_NotifyFlag_InsufficientBuffer) > 0)
                    {
                        BLOCK_SIZE *= 2;
                        Console.WriteLine("[-] Buffer was not sufficient, increasing block size to " + BLOCK_SIZE);

                        // skip this packet
                        long remainingSize1 = (notificationParamBeginOffset + notificationHeader.paramSize) - packetsReader.BaseStream.Position;
                        packetsReader.ReadBytes((int)remainingSize1);
                        break;
                    }

                    if ((notificationHeader.flags & (ushort)dm_NotifyFlag.dm_NotifyFlag_DataDropped) > 0)
                    {
                        TimeSpan timeFromLastDrop = DateTime.Now - this.lastDropTime;

                        if (timeFromLastDrop.TotalMilliseconds > 700)
                            Console.WriteLine("[-] Some packets were dropped.");

                        lastDropTime = DateTime.Now;
                    }

                    long paramsEndOffset = notificationParamBeginOffset + notificationHeader.paramSize;
                    if (packetsReader.BaseStream.Length < paramsEndOffset &&
                        tdevMonitor.ReadMode == dm_ReadMode.dm_ReadMode_Stream)
                    {
                        // We need to read more data so the packet could be read completely
                        long missingSize = paramsEndOffset - packetsReader.BaseStream.Length;
                        AppendToStream(sourceTdevStream.BaseStream, packetsReader.BaseStream, missingSize, true);
                    }

                    ProcessNotification(notificationHeader, packetsReader);

                    long remainingSize = (notificationParamBeginOffset + notificationHeader.paramSize) - packetsReader.BaseStream.Position;
                    byte[] read = packetsReader.ReadBytes((int)remainingSize);
                }

                sw.Stop();
                if (sw.Elapsed.TotalMilliseconds > timePeek) timePeek = sw.Elapsed.TotalMilliseconds;

                streamPosition += packetsReader.BaseStream.Position;
            }
        }

        public void ProcessNotification(dm_NotifyHdr notificationHeader, BinaryReader paramsReader)
        {
            dm_NotifyCode notificationType = (dm_NotifyCode)notificationHeader.code;

            switch (notificationType)
            {
                case dm_NotifyCode.dm_NotifyCode_Write:
                case dm_NotifyCode.dm_NotifyCode_Read:
                case dm_NotifyCode.dm_NotifyCode_FastIoRead:
                case dm_NotifyCode.dm_NotifyCode_FastIoWrite:

                    var writeParams = paramsReader.ReadStruct<dm_ReadWriteNotifyParams>();
                    long remainingParamSize = notificationHeader.paramSize - Marshal.SizeOf(typeof(dm_ReadWriteNotifyParams));
                    if (writeParams.dataSize > remainingParamSize)
                    {
                        // TODO: Remember this packet and expect its continued packet

                        Console.WriteLine("[!] Truncated packet.");
                    }

                    int dataSize = (int)Math.Min(writeParams.dataSize, remainingParamSize);
                    byte[] data = paramsReader.ReadBytes(dataSize);

                    OnReadWritePacketReceived(notificationHeader, writeParams, data, notificationType == dm_NotifyCode.dm_NotifyCode_Write);

                    break;
                case dm_NotifyCode.dm_NotifyCode_Create:
                case dm_NotifyCode.dm_NotifyCode_CreateNamedPipe:

                    dm_CreateNotifyParams createParams = notificationType == dm_NotifyCode.dm_NotifyCode_CreateNamedPipe ?
                        paramsReader.ReadStruct<dm_CreateNamedPipeNotifyParams>().createParams : paramsReader.ReadStruct<dm_CreateNotifyParams>();

                    int pipeFileNameLength = (int)createParams.fileNameLength * 2;
                    string pipeName = Encoding.Unicode.GetString(paramsReader.ReadBytes(pipeFileNameLength));
                    paramsReader.ReadUInt16(); // read the NULL-terminate

                    OnCreatePacketReceived(notificationHeader, createParams, pipeName);

                    break;
                case dm_NotifyCode.dm_NotifyCode_Close:

                    dm_CloseNotifyParams closeParams = paramsReader.ReadStruct<dm_CloseNotifyParams>();
                    OnClosePacketReceived(notificationHeader, closeParams);

                    break;
            }

            if (useExtraStreamBuffering)
            {
                long catchUp = tdevBufferedStream.WritePosition - tdevBufferedStream.ReadPosition;
                //if (catchUp > 1000)
                //    Console.WriteLine("Position catch-up: {0}", catchUp);
            }

        }

        public void OnCreatePacketReceived(dm_NotifyHdr notificationHeader, dm_CreateNotifyParams createParams, string pipeName)
        {
            UInt64 pipeFileIdentifier = createParams.fileIdentifier;

            List<NamedPipeInfo> matchingPipes = namedPipeFiles.Values.Where((x) => x.FileObjects.Contains(pipeFileIdentifier)).ToList();
            if (matchingPipes.Count >= 1)
            {
                // Opening a new file with an already-existing file object? The previous file object must be dead.
                namedPipeFiles.Remove(matchingPipes[0].PipeFileName);
            }

            if (!namedPipeFiles.ContainsKey(pipeName))
            {
                // Create a new pipe
                namedPipeFiles[pipeName] = new NamedPipeInfo(pipeFileIdentifier, pipeName, notificationHeader.processId);

                chromeMonitor.UpdateRunningProcessesCache();
            }
            else
            {
                // We already know this pipe, it must be another process that opens a new handle to it
                namedPipeFiles[pipeName].AddFileObjectIfNeeded(pipeFileIdentifier);
                namedPipeFiles[pipeName].AddProcessIfNeeded(notificationHeader.processId);
            }
        }

        public void OnClosePacketReceived(dm_NotifyHdr notificationHeader, dm_CloseNotifyParams closeParams)
        {
            UInt64 fileID = closeParams.fileId;
            List<NamedPipeInfo> matchingPipes = namedPipeFiles.Values.Where((x) => x.FileObjects.Contains(fileID)).ToList();
            if (matchingPipes.Count != 1 && recordingOnlyNewMojoPipes)
            {
                throw new Exception("I will not suffer inconcicentcies.");
            }

            if (matchingPipes.Count == 1)
                matchingPipes[0].FileObjects.Remove(fileID);
        }

        public void OnReadWritePacketReceived(dm_NotifyHdr notificationHeader, dm_ReadWriteNotifyParams writeParams, byte[] data, bool isWriting)
        {
            UInt64 fileObject = writeParams.fileIdentifier;
            UInt32 processId = notificationHeader.processId;

            if (!chromeMonitor.IsChromeProcess(processId)) return;

            // Find out on which pipe this packet was sent
            NamedPipeInfo pipe = DeterminePipeFromPacket(notificationHeader, writeParams);
            string pipeName = pipe != null ? pipe.PipeFileName : "<Unknown " + fileObject.ToString("X") + ">";

            if (pipe != null)
            {
                // Update this pipe's information
                namedPipeFiles[pipeName].AddProcessIfNeeded(processId);
                namedPipeFiles[pipeName].AddFileObjectIfNeeded(fileObject);
            }

            if (!pipeName.Contains(this.pipeNameFilter)) return;

            //
            // Find out what is the destination process of this packet
            //
            UInt32 destinationPID = 0;
            if (pipe != null)
            {
                if (pipe.InvolvedProcesses.Count < 2 && !destoryedNamedPipes.Contains(pipe.PipeFileName))
                {
                    //
                    // try to find the destination process using Windows handle query
                    //

                    List<int> legalPIDs = ChromeMonitor.GetRunningChromeProcesses().Select(process => process.Id).ToList();
                    string fullPipePath = @"\Device\NamedPipe" + pipe.PipeFileName;
                    namedPipeFiles[pipeName].InvolvedProcesses = HandlesUtility.GetProcessesUsingFile(fullPipePath, legalPIDs);
                    if (namedPipeFiles[pipeName].InvolvedProcesses.Count < 2)
                    {
                        // TODO: because we are doing heavy caching on the handle information, 
                        // it happens sometimes that we reach here but the pipe actually is in fact valid.
                        //Console.WriteLine("[-] Could not find destination PID for " + pipeName);
                        destoryedNamedPipes.Add(pipe.PipeFileName);
                    }

                }

                if (pipe.InvolvedProcesses.Count >= 2)
                {
                    List<uint> involvedProcesses = pipe.InvolvedProcesses.ToList();
                    involvedProcesses.Remove(notificationHeader.processId);
                    destinationPID = involvedProcesses.Last();
                }
            }

            if (!isWriting) return;
            if (data.Length == 0) return;

            //
            // Send it off
            //
            this.numPacketsProcessed++;
            byte[] wiresharkPacket = GenerateWiresharkPacket(notificationHeader, writeParams, pipeName, destinationPID, data);
            wiresharkSender.SendToWiresharkAsEthernet(wiresharkPacket, 0);

        }

        public NamedPipeInfo DeterminePipeFromPacket(dm_NotifyHdr notificationHeader, dm_ReadWriteNotifyParams writeParams)
        {
            UInt64 fileObject = writeParams.fileIdentifier;

            // Search for the pipe by the file object
            List<NamedPipeInfo> matchingPipes = namedPipeFiles.Values.Where((x) => x.FileObjects.Contains(fileObject)).ToList();
            if (matchingPipes.Count == 1) return matchingPipes[0];

            if (destoryedNamedPipes.Contains(fileObject.ToString("X"))) return null;

            if (matchingPipes.Count == 0)
            {
                // We didn't see this file object before.

                if (this.recordingOnlyNewMojoPipes)
                {
                    // are we missing create packets?
                    // we probably do, because we can't read fast enough.
                    throw new Exception("I will not suffer inconsistencies.");
                }

                //
                // Try to get the pipe name from the file object
                //
                string pipeName = HandlesUtility.GetFilePathFromFileObject(new IntPtr((long)fileObject));
                if (pipeName != null && pipeName.Contains(@"\Device\NamedPipe"))
                {
                    pipeName = pipeName.Substring(@"\Device\NamedPipe".Length);

                    if (!namedPipeFiles.ContainsKey(pipeName))
                    {
                        // We don't know this pipe
                        // create it then

                        namedPipeFiles[pipeName] = new NamedPipeInfo(fileObject, pipeName, notificationHeader.processId);
                    }

                    return namedPipeFiles[pipeName];
                }
                else
                {
                    // either the pipe does not exist anymore, or its handle was closed, or NtQueryObject got hang
                }
            }
            else
            {
                // this file object must be dead, because it's used in two pipes
                throw new Exception("I will not suffer inconsistencies.");
            }

            //Console.WriteLine("[-] Could not find pipe name for " + fileObject.ToString("X"));
            destoryedNamedPipes.Add(fileObject.ToString("X"));
            return null;
        }

        public byte[] GenerateWiresharkPacket(TDevMonitor.dm_NotifyHdr header, TDevMonitor.dm_ReadWriteNotifyParams writeParams,
                                              string pipeName, UInt32 destPID, byte[] data)
        {
            MemoryStream memoryStream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(memoryStream);

            UInt32 sourcePID = header.processId;

            writer.Write(header.code);
            writer.Write(sourcePID);
            writer.Write(destPID);
            writer.Write((UInt32)chromeMonitor.GetChromeProcessType(sourcePID));
            writer.Write((UInt32)chromeMonitor.GetChromeProcessType(destPID));
            writer.Write(header.threadId);
            writer.Write(pipeName);
            writer.Write(header.timestamp);
            writer.Write(writeParams.dataSize);

            writer.Write(data);

            return memoryStream.ToArray();
        }

        public void Stop()
        {
            this.isShuttingDown = true;
            this.tdevMonitor.Stop();
        }

        public void ExtraBufferingReadingLoop()
        {
            BinaryReader reader = new BinaryReader(this.tdevStream.BaseStream);

            byte[] buffer = new byte[BLOCK_SIZE];
            int read;
            while ((read = reader.Read(buffer, 0, buffer.Length)) > 0)
            {
                tdevBufferedStream.Write(buffer, 0, read);
            }
        }


        public int AppendToStream(Stream sourceStream, Stream destinationStream, long count, bool atLeast = false)
        {
            int miniumReadSize = Marshal.SizeOf(typeof(dm_NotifyHdr));
            long fixedCount = Math.Max(count, miniumReadSize);

            byte[] buffer = new byte[fixedCount];
            int read = sourceStream.Read(buffer, 0, buffer.Length);

            if (read < count && atLeast)
            {
                while (read < count)
                {
                    int toRead = Math.Max(buffer.Length - read, miniumReadSize);
                    if (read + toRead > buffer.Length) Array.Resize(ref buffer, read + toRead);

                    read += sourceStream.Read(buffer, read, toRead);
                }
            }

            long originalPosition = destinationStream.Position;
            destinationStream.Seek(0, SeekOrigin.End);
            destinationStream.Write(buffer, 0, read);
            destinationStream.Seek(originalPosition, SeekOrigin.Begin);

            if (recordStream)
                replayStreamWriter.BaseStream.Write(buffer, 0, read);

            return read;
        }

    }

}
