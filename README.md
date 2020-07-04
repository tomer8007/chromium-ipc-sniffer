# Chromium IPC Sniffer
This utility helps you explore what Chrome processes are saying to each other under the hood in real-time, using Wireshark.

It captures data sent over the [Named Pipe](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes) IPC primitive and sends it over to dissection.

<img src="https://raw.githubusercontent.com/tomer8007/chromium-ipc-sniffer/master/screenshot_3.png" >

## Supported protocol and formats
* Mojo Core (Ports, Invitations, Handles, etc.)
* Mojo user messages (actual `.mojom` IDL method calls)
* Legacy IPC
* Mojo data pipe control messages (read/wrote X bytes)
* Audio sync messages (`\pipe\chrome.sync.xxxxx`)

However, this project won't see anything that doesn't go over pipes, which is mostly shared memory IPC:
* Mojo data pipe contents (real time networking buffers, audio, etc.)
* Sandbox IPC
* Possibly more things

## Usage
You can download the pre-compiled binaries from the Releases page, and run:
```
C:\>chromeipc.exe

Chrome IPC Sniffer v0.5.0.0

Type -h to get usage help and extended options

[+] Starting up
[+] Determining your chromium version
[+] You are using chromium 83.0.4103.116
[+] Checking mojom interfaces information
[+] Checking legacy IPC interfaces information
[+] Extracting scrambled message IDs from chrome.dll...
[+] Copying LUA dissectors to Wirehsark plugins directory
[+] Enumerating existing chrome pipes
[+] Starting sniffing of chrome named pipe to \\.\pipe\chromeipc.
[+] Opening Wirehark
[+] Capturing 40 packets/second......
```

Wireshark should open automatically.
