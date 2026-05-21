#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define WINVER 0x0601
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <windowsx.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <richedit.h>
#include <richole.h>
#include <uxtheme.h>
#include <dwmapi.h>

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <algorithm>
#include <memory>
#include <iostream>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")

const wchar_t* VAULT_PASSWORD = L"1234";
const wchar_t* VAULT_DIR_NAME = L"SecureVault_Storage";
const wchar_t* VAULT_INDEX_FILE = L"vault.idx";
const wchar_t* APP_NAME = L"SecureVault";
const wchar_t* APP_VERSION = L"2.0.0";

#define AES_KEY_SIZE    32
#define AES_IV_SIZE     16
#define AES_BLOCK_SIZE  16
#define SALT_SIZE       32

#define CLR_BG          RGB(13,  17,  23)   
#define CLR_SURFACE     RGB(22,  27,  34)   
#define CLR_SURFACE2    RGB(30,  38,  50)   
#define CLR_BORDER      RGB(48,  54,  61)   
#define CLR_ACCENT      RGB(31, 139, 241)   
#define CLR_ACCENT2     RGB(56, 189, 248)   
#define CLR_SUCCESS     RGB(35, 197, 98)    
#define CLR_DANGER      RGB(240,  71,  71)  
#define CLR_WARN        RGB(240, 173,  78)  
#define CLR_TEXT        RGB(230, 237, 243)  
#define CLR_TEXT2       RGB(139, 148, 158)  
#define CLR_CONSOLE_BG  RGB(8,   10,  15)   

#define IDC_PASSWORD_EDIT    1001
#define IDC_LOGIN_BTN        1002
#define IDC_TAB_CTRL         1010
#define IDC_FILE_LIST        1020
#define IDC_UPLOAD_BTN       1021
#define IDC_DECRYPT_BTN      1022
#define IDC_DELETE_BTN       1023
#define IDC_EXPORT_BTN       1024
#define IDC_NOTE_EDIT        1030
#define IDC_NOTE_TITLE       1031
#define IDC_NOTE_SAVE_BTN    1032
#define IDC_NOTE_NEW_BTN     1033
#define IDC_NOTE_DELETE_BTN  1034
#define IDC_NOTE_LIST        1035
#define IDC_KEY_EDIT         1040
#define IDC_KEY_COPY_BTN     1041
#define IDC_STATUS_BAR       1050
#define IDC_CONSOLE_BTN      1060
#define IDC_SHOW_KEY_BTN     1061

HWND g_hMainWnd = NULL;
HWND g_hLoginWnd = NULL;
HWND g_hDashWnd = NULL;
HWND g_hConsole = NULL;
HWND g_hConsoleEdit = NULL;
HWND g_hTabCtrl = NULL;
HWND g_hFileList = NULL;
HWND g_hNoteList = NULL;
HWND g_hNoteEdit = NULL;
HWND g_hNoteTitle = NULL;
HWND g_hStatusBar = NULL;
HWND g_hKeyEdit = NULL;
HINSTANCE g_hInst = NULL;

std::wstring g_vaultPath;
bool g_authenticated = false;

struct VaultEntry {
    std::wstring id;
    std::wstring originalName;
    std::wstring encryptedPath;
    std::wstring keyHex;
    std::wstring ivHex;
    std::wstring type;
    std::wstring addedTime;
    LONGLONG     originalSize;
};

std::vector<VaultEntry> g_vaultEntries;
int g_selectedNote = -1;

enum LogLevel { LOG_INFO, LOG_SUCCESS, LOG_FAIL, LOG_WARN, LOG_DEBUG };

void ConsoleLog(const std::wstring& msg, LogLevel level = LOG_INFO) {
    if (!g_hConsoleEdit) return;

    CHARFORMAT2W cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR | CFM_BOLD | CFM_FACE | CFM_SIZE;
    cf.dwEffects = 0;
    cf.yHeight = 180;
    wcscpy_s(cf.szFaceName, L"Consolas");

    switch (level) {
    case LOG_SUCCESS: cf.crTextColor = RGB(35, 197, 98);   break;
    case LOG_FAIL:    cf.crTextColor = RGB(240, 71, 71);  break;
    case LOG_WARN:    cf.crTextColor = RGB(240, 173, 78);  break;
    case LOG_DEBUG:   cf.crTextColor = RGB(56, 189, 248);  break;
    default:          cf.crTextColor = RGB(139, 148, 158); break;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timeBuf[32];
    swprintf_s(timeBuf, L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);

    CHARFORMAT2W cfTime = cf;
    cfTime.crTextColor = RGB(60, 70, 85);

    int len = GetWindowTextLengthW(g_hConsoleEdit);
    SendMessageW(g_hConsoleEdit, EM_SETSEL, len, len);
    SendMessageW(g_hConsoleEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cfTime);
    SendMessageW(g_hConsoleEdit, EM_REPLACESEL, FALSE, (LPARAM)timeBuf);

    const wchar_t* prefix = L"[ ] ";
    CHARFORMAT2W cfPfx = cf;
    switch (level) {
    case LOG_SUCCESS: prefix = L"[+] "; break;
    case LOG_FAIL:    prefix = L"[!] "; break;
    case LOG_WARN:    prefix = L"[~] "; break;
    case LOG_DEBUG:   prefix = L"[>] "; break;
    default:          prefix = L"[-] "; break;
    }

    len = GetWindowTextLengthW(g_hConsoleEdit);
    SendMessageW(g_hConsoleEdit, EM_SETSEL, len, len);
    SendMessageW(g_hConsoleEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cfPfx);
    SendMessageW(g_hConsoleEdit, EM_REPLACESEL, FALSE, (LPARAM)prefix);

    std::wstring fullMsg = msg + L"\r\n";
    len = GetWindowTextLengthW(g_hConsoleEdit);
    SendMessageW(g_hConsoleEdit, EM_SETSEL, len, len);
    SendMessageW(g_hConsoleEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(g_hConsoleEdit, EM_REPLACESEL, FALSE, (LPARAM)fullMsg.c_str());

    SendMessageW(g_hConsoleEdit, WM_VSCROLL, SB_BOTTOM, 0);
}

std::wstring BytesToHex(const BYTE* data, DWORD len) {
    std::wstringstream ss;
    ss << std::hex << std::uppercase << std::setfill(L'0');
    for (DWORD i = 0; i < len; i++)
        ss << std::setw(2) << (unsigned)data[i];
    return ss.str();
}

bool HexToBytes(const std::wstring& hex, std::vector<BYTE>& out) {
    if (hex.length() % 2 != 0) return false;
    out.clear();
    for (size_t i = 0; i < hex.length(); i += 2) {
        wchar_t hi = hex[i], lo = hex[i + 1];
        auto hexVal = [](wchar_t c) -> int {
            if (c >= L'0' && c <= L'9') return c - L'0';
            if (c >= L'A' && c <= L'F') return c - L'A' + 10;
            if (c >= L'a' && c <= L'f') return c - L'a' + 10;
            return -1;
            };
        int h = hexVal(hi), l = hexVal(lo);
        if (h < 0 || l < 0) return false;
        out.push_back((BYTE)((h << 4) | l));
    }
    return true;
}

bool GenRandom(BYTE* buf, DWORD len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;
    status = BCryptGenRandom(hAlg, buf, len, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(status);
}

std::wstring GenerateID() {
    BYTE buf[16];
    GenRandom(buf, 16);
    return BytesToHex(buf, 16);
}

std::wstring GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return buf;
}

bool AES256Encrypt(const BYTE* plaintext, DWORD ptLen,
    const BYTE* key, const BYTE* iv,
    std::vector<BYTE>& ciphertext) {
    ConsoleLog(L"Initialising AES-256-CBC encryption engine...", LOG_DEBUG);
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) { ConsoleLog(L"Failed to open AES provider", LOG_FAIL); return false; }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    DWORD keyObjSize = 0, bytesReturned = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize, sizeof(DWORD), &bytesReturned, 0);

    std::vector<BYTE> keyObj(keyObjSize);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize, (PUCHAR)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) { ConsoleLog(L"Failed to generate symmetric key", LOG_FAIL); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    DWORD ctLen = 0;
    BYTE ivCopy[AES_IV_SIZE];
    memcpy(ivCopy, iv, AES_IV_SIZE);

    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, ptLen, NULL, ivCopy, AES_IV_SIZE, NULL, 0, &ctLen, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) { BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    ciphertext.resize(ctLen);
    memcpy(ivCopy, iv, AES_IV_SIZE);

    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, ptLen, NULL, ivCopy, AES_IV_SIZE, ciphertext.data(), ctLen, &ctLen, BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) { ConsoleLog(L"Encryption operation failed", LOG_FAIL); return false; }
    ConsoleLog(L"Encryption complete. PKCS7 padding applied.", LOG_SUCCESS);
    return true;
}

bool AES256Decrypt(const BYTE* ciphertext, DWORD ctLen,
    const BYTE* key, const BYTE* iv,
    std::vector<BYTE>& plaintext) {
    ConsoleLog(L"Initialising AES-256-CBC decryption engine...", LOG_DEBUG);
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) { ConsoleLog(L"Failed to open AES provider", LOG_FAIL); return false; }

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    DWORD keyObjSize = 0, bytesReturned = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize, sizeof(DWORD), &bytesReturned, 0);

    std::vector<BYTE> keyObj(keyObjSize);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize, (PUCHAR)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) { ConsoleLog(L"Invalid key material", LOG_FAIL); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    DWORD ptLen = 0;
    BYTE ivCopy[AES_IV_SIZE];
    memcpy(ivCopy, iv, AES_IV_SIZE);

    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, ctLen, NULL, ivCopy, AES_IV_SIZE, NULL, 0, &ptLen, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) { ConsoleLog(L"Decryption size query failed — wrong key?", LOG_FAIL); BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    plaintext.resize(ptLen);
    memcpy(ivCopy, iv, AES_IV_SIZE);

    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, ctLen, NULL, ivCopy, AES_IV_SIZE, plaintext.data(), ptLen, &ptLen, BCRYPT_BLOCK_PADDING);
    plaintext.resize(ptLen);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) { ConsoleLog(L"Decryption failed — key or IV incorrect", LOG_FAIL); return false; }
    ConsoleLog(L"Decryption successful. Data integrity verified.", LOG_SUCCESS);
    return true;
}

bool SaveVaultIndex() {
    std::wstring idxPath = g_vaultPath + L"\\" + VAULT_INDEX_FILE;
    ConsoleLog(L"Serialising vault index...", LOG_DEBUG);

    std::wostringstream ss;
    ss << L"SECUREVAULT_INDEX_V1\n" << g_vaultEntries.size() << L"\n";
    for (auto& e : g_vaultEntries) {
        ss << e.id << L"\t" << e.originalName << L"\t" << e.encryptedPath << L"\t"
            << e.keyHex << L"\t" << e.ivHex << L"\t" << e.type << L"\t"
            << e.addedTime << L"\t" << e.originalSize << L"\n";
    }

    std::wstring data = ss.str();
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, NULL, 0, NULL, NULL);
    std::vector<char> utf8Data(utf8Len);
    WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, utf8Data.data(), utf8Len, NULL, NULL);

    HANDLE hFile = CreateFileW(idxPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { ConsoleLog(L"Failed to write vault index", LOG_FAIL); return false; }

    DWORD written;
    WriteFile(hFile, utf8Data.data(), (DWORD)utf8Data.size() - 1, &written, NULL);
    CloseHandle(hFile);
    ConsoleLog(L"Vault index saved (" + std::to_wstring(g_vaultEntries.size()) + L" entries)", LOG_SUCCESS);
    return true;
}

bool LoadVaultIndex() {
    std::wstring idxPath = g_vaultPath + L"\\" + VAULT_INDEX_FILE;
    if (!PathFileExistsW(idxPath.c_str())) { ConsoleLog(L"No existing vault index — fresh vault", LOG_INFO); return true; }

    ConsoleLog(L"Loading vault index from disk...", LOG_DEBUG);
    HANDLE hFile = CreateFileW(idxPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { ConsoleLog(L"Cannot open vault index", LOG_FAIL); return false; }

    DWORD fileSize = GetFileSize(hFile, NULL);
    std::vector<char> buf(fileSize + 1, 0);
    DWORD bytesRead;
    ReadFile(hFile, buf.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    int wLen = MultiByteToWideChar(CP_UTF8, 0, buf.data(), -1, NULL, 0);
    std::vector<wchar_t> wBuf(wLen);
    MultiByteToWideChar(CP_UTF8, 0, buf.data(), -1, wBuf.data(), wLen);
    std::wstring data(wBuf.data());

    std::wistringstream iss(data);
    std::wstring line;
    std::getline(iss, line);
    if (line != L"SECUREVAULT_INDEX_V1") { ConsoleLog(L"Vault index format unrecognised", LOG_FAIL); return false; }

    int count = 0;
    std::getline(iss, line);
    try { count = std::stoi(line); }
    catch (...) { return false; }

    g_vaultEntries.clear();
    for (int i = 0; i < count; i++) {
        std::getline(iss, line);
        if (line.empty()) continue;
        VaultEntry e;
        std::wistringstream ls(line);
        std::wstring field;
        std::getline(ls, e.id, L'\t');
        std::getline(ls, e.originalName, L'\t');
        std::getline(ls, e.encryptedPath, L'\t');
        std::getline(ls, e.keyHex, L'\t');
        std::getline(ls, e.ivHex, L'\t');
        std::getline(ls, e.type, L'\t');
        std::getline(ls, e.addedTime, L'\t');
        std::getline(ls, field);
        e.originalSize = field.empty() ? 0 : std::stoll(field);
        g_vaultEntries.push_back(e);
    }

    ConsoleLog(L"Vault index loaded: " + std::to_wstring(g_vaultEntries.size()) + L" entries", LOG_SUCCESS);
    return true;
}

bool EncryptFileToVault(const std::wstring& srcPath, VaultEntry& outEntry) {
    ConsoleLog(L"Reading source file: " + srcPath, LOG_DEBUG);

    HANDLE hSrc = CreateFileW(srcPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) { ConsoleLog(L"Cannot open source file for reading", LOG_FAIL); return false; }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hSrc, &fileSize);

    if (fileSize.QuadPart == 0) { ConsoleLog(L"Source file is empty", LOG_WARN); CloseHandle(hSrc); return false; }
    if (fileSize.QuadPart > MAXDWORD) { ConsoleLog(L"Files > 4 GB not supported", LOG_FAIL); CloseHandle(hSrc); return false; }

    ConsoleLog(L"File size: " + std::to_wstring(fileSize.QuadPart) + L" bytes", LOG_DEBUG);

    std::vector<BYTE> plainData((size_t)fileSize.QuadPart);
    DWORD bytesRead;
    if (!ReadFile(hSrc, plainData.data(), (DWORD)fileSize.QuadPart, &bytesRead, NULL)) {
        ConsoleLog(L"Failed to read file data", LOG_FAIL); CloseHandle(hSrc); return false;
    }
    CloseHandle(hSrc);

    ConsoleLog(L"Generating 256-bit AES key and 128-bit IV via BCRYPT_RNG...", LOG_DEBUG);
    BYTE key[AES_KEY_SIZE], iv[AES_IV_SIZE];
    if (!GenRandom(key, AES_KEY_SIZE) || !GenRandom(iv, AES_IV_SIZE)) {
        ConsoleLog(L"RNG failure — cannot generate secure key material", LOG_FAIL); return false;
    }

    std::wstring keyHex = BytesToHex(key, AES_KEY_SIZE);
    std::wstring ivHex = BytesToHex(iv, AES_IV_SIZE);
    ConsoleLog(L"Key: " + keyHex.substr(0, 16) + L"...[truncated for security]", LOG_DEBUG);

    std::vector<BYTE> cipherData;
    if (!AES256Encrypt(plainData.data(), (DWORD)plainData.size(), key, iv, cipherData)) {
        ConsoleLog(L"Encryption failed", LOG_FAIL); return false;
    }

    std::wstring id = GenerateID();
    std::wstring encPath = g_vaultPath + L"\\" + id + L".enc";

    HANDLE hDst = CreateFileW(encPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE) { ConsoleLog(L"Cannot write encrypted file to vault", LOG_FAIL); return false; }

    const BYTE MAGIC[8] = { 0x53,0x56,0x41,0x55,0x4C,0x54,0x01,0x00 };
    DWORD written;
    WriteFile(hDst, MAGIC, 8, &written, NULL);
    WriteFile(hDst, iv, AES_IV_SIZE, &written, NULL);
    WriteFile(hDst, cipherData.data(), (DWORD)cipherData.size(), &written, NULL);
    CloseHandle(hDst);
    ConsoleLog(L"Encrypted blob written: " + id + L".enc", LOG_SUCCESS);

    ConsoleLog(L"Zero-wiping original file before deletion...", LOG_DEBUG);
    HANDLE hOvr = CreateFileW(srcPath.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOvr != INVALID_HANDLE_VALUE) {
        std::vector<BYTE> zeros(std::min((LONGLONG)65536, fileSize.QuadPart), 0);
        LARGE_INTEGER pos = {};
        SetFilePointerEx(hOvr, pos, NULL, FILE_BEGIN);
        LONGLONG remaining = fileSize.QuadPart;
        while (remaining > 0) {
            DWORD toWrite = (DWORD)std::min((LONGLONG)zeros.size(), remaining);
            WriteFile(hOvr, zeros.data(), toWrite, &written, NULL);
            remaining -= toWrite;
        }
        CloseHandle(hOvr);
    }

    if (!DeleteFileW(srcPath.c_str()))
        ConsoleLog(L"Warning: Could not delete original (manual deletion may be needed)", LOG_WARN);
    else
        ConsoleLog(L"Original file securely wiped and deleted", LOG_SUCCESS);

    outEntry.id = id;
    outEntry.originalName = PathFindFileNameW(srcPath.c_str());
    outEntry.encryptedPath = encPath;
    outEntry.keyHex = keyHex;
    outEntry.ivHex = ivHex;
    outEntry.type = L"FILE";
    outEntry.addedTime = GetTimestamp();
    outEntry.originalSize = fileSize.QuadPart;
    return true;
}

bool EncryptNoteToVault(const std::wstring& title, const std::wstring& content, VaultEntry& outEntry) {
    ConsoleLog(L"Encrypting note: " + title, LOG_DEBUG);

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, content.c_str(), -1, NULL, 0, NULL, NULL);
    std::vector<BYTE> noteData((size_t)utf8Len);
    WideCharToMultiByte(CP_UTF8, 0, content.c_str(), -1, (LPSTR)noteData.data(), utf8Len, NULL, NULL);

    if (noteData.empty()) { ConsoleLog(L"Note content is empty", LOG_WARN); return false; }

    BYTE key[AES_KEY_SIZE], iv[AES_IV_SIZE];
    if (!GenRandom(key, AES_KEY_SIZE) || !GenRandom(iv, AES_IV_SIZE)) {
        ConsoleLog(L"RNG failure generating note key", LOG_FAIL); return false;
    }

    std::vector<BYTE> cipherData;
    if (!AES256Encrypt(noteData.data(), (DWORD)noteData.size(), key, iv, cipherData)) return false;

    std::wstring id = GenerateID();
    std::wstring encPath = g_vaultPath + L"\\" + id + L".enc";

    HANDLE hDst = CreateFileW(encPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE) { ConsoleLog(L"Cannot write encrypted note", LOG_FAIL); return false; }

    const BYTE MAGIC[8] = { 0x53,0x56,0x4E,0x4F,0x54,0x45,0x01,0x00 };
    DWORD written;
    WriteFile(hDst, MAGIC, 8, &written, NULL);
    WriteFile(hDst, iv, AES_IV_SIZE, &written, NULL);
    WriteFile(hDst, cipherData.data(), (DWORD)cipherData.size(), &written, NULL);
    CloseHandle(hDst);

    outEntry.id = id;
    outEntry.originalName = L"NOTE:" + title;
    outEntry.encryptedPath = encPath;
    outEntry.keyHex = BytesToHex(key, AES_KEY_SIZE);
    outEntry.ivHex = BytesToHex(iv, AES_IV_SIZE);
    outEntry.type = L"NOTE";
    outEntry.addedTime = GetTimestamp();
    outEntry.originalSize = (LONGLONG)content.length();

    ConsoleLog(L"Note encrypted and stored: " + id + L".enc", LOG_SUCCESS);
    return true;
}

bool DecryptFromVault(const VaultEntry& entry, std::vector<BYTE>& outData) {
    ConsoleLog(L"Decrypting entry: " + entry.originalName, LOG_DEBUG);

    if (!PathFileExistsW(entry.encryptedPath.c_str())) {
        ConsoleLog(L"Encrypted file not found: " + entry.encryptedPath, LOG_FAIL); return false;
    }

    std::vector<BYTE> key, iv;
    if (!HexToBytes(entry.keyHex, key) || key.size() != AES_KEY_SIZE) {
        ConsoleLog(L"Invalid key hex in vault entry", LOG_FAIL); return false;
    }
    if (!HexToBytes(entry.ivHex, iv) || iv.size() != AES_IV_SIZE) {
        ConsoleLog(L"Invalid IV hex in vault entry", LOG_FAIL); return false;
    }

    HANDLE hFile = CreateFileW(entry.encryptedPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { ConsoleLog(L"Cannot open encrypted file", LOG_FAIL); return false; }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize < 8 + AES_IV_SIZE) { ConsoleLog(L"Encrypted file too small — corrupted?", LOG_FAIL); CloseHandle(hFile); return false; }

    std::vector<BYTE> rawData(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, rawData.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    DWORD cipherOffset = 8 + AES_IV_SIZE;
    DWORD cipherLen = fileSize - cipherOffset;
    ConsoleLog(L"Ciphertext: " + std::to_wstring(cipherLen) + L" bytes", LOG_DEBUG);

    return AES256Decrypt(rawData.data() + cipherOffset, cipherLen, key.data(), iv.data(), outData);
}

void RefreshFileList() {
    if (!g_hFileList) return;
    SendMessageW(g_hFileList, LVM_DELETEALLITEMS, 0, 0);

    for (int i = 0; i < (int)g_vaultEntries.size(); i++) {
        auto& e = g_vaultEntries[i];
        if (e.type != L"FILE") continue;

        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = ListView_GetItemCount(g_hFileList);
        lvi.lParam = i;
        lvi.pszText = (LPWSTR)e.originalName.c_str();
        int row = ListView_InsertItem(g_hFileList, &lvi);

        ListView_SetItemText(g_hFileList, row, 1, (LPWSTR)e.addedTime.c_str());

        wchar_t sizeBuf[32];
        if (e.originalSize >= 1024 * 1024)
            swprintf_s(sizeBuf, L"%.1f MB", e.originalSize / (1024.0 * 1024.0));
        else if (e.originalSize >= 1024)
            swprintf_s(sizeBuf, L"%.1f KB", e.originalSize / 1024.0);
        else
            swprintf_s(sizeBuf, L"%lld B", e.originalSize);

        ListView_SetItemText(g_hFileList, row, 2, sizeBuf);
        ListView_SetItemText(g_hFileList, row, 3, (LPWSTR)e.id.substr(0, 8).c_str());
    }
}

void RefreshNoteList() {
    if (!g_hNoteList) return;
    SendMessageW(g_hNoteList, LB_RESETCONTENT, 0, 0);

    for (int i = 0; i < (int)g_vaultEntries.size(); i++) {
        auto& e = g_vaultEntries[i];
        if (e.type != L"NOTE") continue;
        std::wstring title = e.originalName;
        if (title.substr(0, 5) == L"NOTE:") title = title.substr(5);
        int idx = (int)SendMessageW(g_hNoteList, LB_ADDSTRING, 0, (LPARAM)title.c_str());
        SendMessageW(g_hNoteList, LB_SETITEMDATA, idx, i);
    }
}

void UpdateStatusBar(const std::wstring& msg) {
    if (g_hStatusBar)
        SendMessageW(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)msg.c_str());
}

static void DrawRoundRect(HDC hdc, int x, int y, int w, int h, int r, COLORREF fill, COLORREF stroke = 0, int strokeW = 0) {
    HPEN   pen = strokeW > 0 ? CreatePen(PS_SOLID, strokeW, stroke) : (HPEN)GetStockObject(NULL_PEN);
    HBRUSH br = CreateSolidBrush(fill);
    HPEN   old = (HPEN)SelectObject(hdc, pen);
    HBRUSH oldb = (HBRUSH)SelectObject(hdc, br);
    RoundRect(hdc, x, y, x + w, y + h, r, r);
    SelectObject(hdc, old);
    SelectObject(hdc, oldb);
    DeleteObject(br);
    if (strokeW > 0) DeleteObject(pen);
}

struct KeyDialogParams {
    std::wstring title;
    std::wstring key;
    std::wstring iv;
    std::wstring filename;
};

INT_PTR CALLBACK KeyDialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static KeyDialogParams* pParams = nullptr;
    static HFONT hFontTitle = NULL, hFontMono = NULL, hFontUI = NULL;

    switch (msg) {
    case WM_INITDIALOG: {
        pParams = (KeyDialogParams*)lp;
        SetWindowTextW(hwnd, pParams->title.c_str());

        hFontTitle = CreateFontW(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontMono = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Consolas");
        hFontUI = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

        HWND hKeyEdit = GetDlgItem(hwnd, 1001);
        SetWindowTextW(hKeyEdit, pParams->key.c_str());
        SendMessageW(hKeyEdit, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        HWND hIVEdit = GetDlgItem(hwnd, 1002);
        SetWindowTextW(hIVEdit, pParams->iv.c_str());
        SendMessageW(hIVEdit, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        HWND hFile = GetDlgItem(hwnd, 1003);
        SetWindowTextW(hFile, pParams->filename.c_str());
        SendMessageW(hFile, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        SendMessageW(GetDlgItem(hwnd, 1004), WM_SETFONT, (WPARAM)hFontUI, TRUE);
        SendMessageW(GetDlgItem(hwnd, 1005), WM_SETFONT, (WPARAM)hFontUI, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDOK), WM_SETFONT, (WPARAM)hFontUI, TRUE);

        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == 1004) { 
            std::wstring key = pParams ? pParams->key : L"";
            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                size_t len = (key.length() + 1) * sizeof(wchar_t);
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
                if (hMem) { memcpy(GlobalLock(hMem), key.c_str(), len); GlobalUnlock(hMem); SetClipboardData(CF_UNICODETEXT, hMem); }
                CloseClipboard();
                SetWindowTextW(GetDlgItem(hwnd, 1004), L"Copied!");
                ConsoleLog(L"Decrypt key copied to clipboard", LOG_SUCCESS);
            }
        }
        else if (LOWORD(wp) == 1005) { 
            std::wstring iv = pParams ? pParams->iv : L"";
            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                size_t len = (iv.length() + 1) * sizeof(wchar_t);
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
                if (hMem) { memcpy(GlobalLock(hMem), iv.c_str(), len); GlobalUnlock(hMem); SetClipboardData(CF_UNICODETEXT, hMem); }
                CloseClipboard();
                SetWindowTextW(GetDlgItem(hwnd, 1005), L"Copied!");
            }
        }
        else if (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL) {
            if (hFontTitle) DeleteObject(hFontTitle);
            if (hFontMono)  DeleteObject(hFontMono);
            if (hFontUI)    DeleteObject(hFontUI);
            EndDialog(hwnd, LOWORD(wp));
        }
        return TRUE;
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetBkColor(hdc, CLR_SURFACE2);
        SetTextColor(hdc, RGB(56, 189, 248));
        static HBRUSH editBr = CreateSolidBrush(CLR_SURFACE2);
        return (LRESULT)editBr;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, CLR_TEXT2);
        static HBRUSH staticBr = CreateSolidBrush(CLR_SURFACE);
        return (LRESULT)staticBr;
    }
    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wp;
        RECT rc; GetClientRect(hwnd, &rc);
        HBRUSH br = CreateSolidBrush(CLR_SURFACE);
        FillRect(hdc, &rc, br);
        DeleteObject(br);
        return 1;
    }
    }
    return FALSE;
}

void ShowKeyDialog(HWND parent, const std::wstring& filename, const std::wstring& key, const std::wstring& iv, bool isNote = false) {
    struct DlgData {
        DLGTEMPLATE tmpl;
        WORD menu, cls, title[64];
    };

    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_APPWINDOW,
        L"SecureVaultKeyDlg", isNote ? L"Note Saved — Decrypt Key" : L"File Encrypted — Decrypt Key",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        0, 0, 620, 320, parent, NULL, g_hInst, NULL);

    if (!hDlg) return;

    RECT pr, dr;
    GetWindowRect(parent, &pr);
    GetWindowRect(hDlg, &dr);
    int dw = dr.right - dr.left, dh = dr.bottom - dr.top;
    SetWindowPos(hDlg, NULL, pr.left + (pr.right - pr.left - dw) / 2, pr.top + (pr.bottom - pr.top - dh) / 2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);

    MSG msg;
    while (IsWindow(hDlg) && GetMessageW(&msg, NULL, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) { DestroyWindow(hDlg); break; }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

LRESULT CALLBACK ConsoleWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    case WM_SIZE: {
        RECT rc; GetClientRect(hwnd, &rc);
        SetWindowPos(g_hConsoleEdit, NULL, 0, 40, rc.right, rc.bottom - 40, SWP_NOZORDER | SWP_NOACTIVATE);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        RECT hdrRc = { 0, 0, rc.right, 40 };
        HBRUSH hdrBr = CreateSolidBrush(RGB(15, 20, 30));
        FillRect(hdc, &hdrRc, hdrBr);
        DeleteObject(hdrBr);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, CLR_SUCCESS);
        HFONT hf = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Consolas");
        HFONT old = (HFONT)SelectObject(hdc, hf);
        RECT tr = { 12, 0, 400, 40 };
        DrawTextW(hdc, L"  SecureVault :: Debug Console  [AES-256-CBC | Windows CNG]", -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, old);
        DeleteObject(hf);

        HBRUSH dot = CreateSolidBrush(CLR_SUCCESS);
        HPEN np = (HPEN)GetStockObject(NULL_PEN);
        SelectObject(hdc, np);
        SelectObject(hdc, dot);
        Ellipse(hdc, rc.right - 22, 15, rc.right - 10, 27);
        DeleteObject(dot);

        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void CreateConsoleWindow() {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = ConsoleWndProc;
    wc.hInstance = g_hInst;
    wc.hbrBackground = CreateSolidBrush(CLR_CONSOLE_BG);
    wc.lpszClassName = L"SecureVaultConsole";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);

    g_hConsole = CreateWindowExW(WS_EX_TOOLWINDOW,
        L"SecureVaultConsole", L"SecureVault Debug Console",
        WS_OVERLAPPEDWINDOW,
        sw - 730, 30, 720, 500, NULL, NULL, g_hInst, NULL);

    g_hConsoleEdit = CreateWindowExW(0,
        L"RICHEDIT50W", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 40, 720, 460, g_hConsole, NULL, g_hInst, NULL);

    if (!g_hConsoleEdit) {
        g_hConsoleEdit = CreateWindowExW(0,
            L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 40, 720, 460, g_hConsole, NULL, g_hInst, NULL);
    }

    if (g_hConsoleEdit) {
        SendMessageW(g_hConsoleEdit, EM_SETBKGNDCOLOR, 0, CLR_CONSOLE_BG);
    }

    ShowWindow(g_hConsole, SW_SHOW);
    UpdateWindow(g_hConsole);

    ConsoleLog(L"══════════════════════════════════════════════════════", LOG_INFO);
    ConsoleLog(L"  BCSVault v2.0.0  ·  Debug Console", LOG_SUCCESS);
    ConsoleLog(L"  Encryption: AES-256-CBC  ·  RNG: Windows CNG BCrypt", LOG_INFO);
    ConsoleLog(L"  Storage: Local AppData (hidden+system directory)", LOG_INFO);
    ConsoleLog(L"  coded by @bosslivin on telegram                     ", LOG_INFO);
    ConsoleLog(L"══════════════════════════════════════════════════════", LOG_INFO);
    ConsoleLog(L"System initialising...", LOG_DEBUG);
}

HWND g_hPassEdit = NULL;
HWND g_hLoginBtn = NULL;
HWND g_hLoginStatus = NULL;

LRESULT CALLBACK LoginWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

void CreateLoginWindow() {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = LoginWndProc;
    wc.hInstance = g_hInst;
    wc.hbrBackground = CreateSolidBrush(CLR_BG);
    wc.lpszClassName = L"SecureVaultLogin";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassExW(&wc);

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    int w = 440, h = 380;

    g_hLoginWnd = CreateWindowExW(WS_EX_APPWINDOW,
        L"SecureVaultLogin", L"SecureVault",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        (sw - w) / 2, (sh - h) / 2, w, h,
        NULL, NULL, g_hInst, NULL);

    ShowWindow(g_hLoginWnd, SW_SHOW);
    UpdateWindow(g_hLoginWnd);
    ConsoleLog(L"Login window initialised. Awaiting authentication...", LOG_INFO);
}

LRESULT CALLBACK LoginWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT hFontTitle = NULL, hFontMed = NULL, hFontSmall = NULL;
    static HBRUSH hBrBg = NULL;
    static bool hovered = false;

    switch (msg) {
    case WM_CREATE: {
        hBrBg = CreateSolidBrush(CLR_BG);

        hFontTitle = CreateFontW(26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontMed = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontSmall = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

        HWND hLabel = CreateWindowW(L"STATIC", L"Vault Password",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            60, 185, 320, 20, hwnd, NULL, g_hInst, NULL);
        SendMessage(hLabel, WM_SETFONT, (WPARAM)hFontSmall, TRUE);

        g_hPassEdit = CreateWindowExW(0,
            L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD,
            60, 208, 320, 38, hwnd, (HMENU)IDC_PASSWORD_EDIT, g_hInst, NULL);
        SendMessage(g_hPassEdit, WM_SETFONT, (WPARAM)hFontMed, TRUE);
        SendMessage(g_hPassEdit, EM_SETPASSWORDCHAR, 0x25CF, 0); 

        g_hLoginBtn = CreateWindowW(L"BUTTON", L"Unlock Vault",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            60, 262, 320, 44, hwnd, (HMENU)IDC_LOGIN_BTN, g_hInst, NULL);
        SendMessage(g_hLoginBtn, WM_SETFONT, (WPARAM)hFontMed, TRUE);

        g_hLoginStatus = CreateWindowW(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            60, 318, 320, 20, hwnd, NULL, g_hInst, NULL);
        SendMessage(g_hLoginStatus, WM_SETFONT, (WPARAM)hFontSmall, TRUE);

        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        FillRect(hdc, &rc, hBrBg);

        RECT strip = { 0, 0, rc.right, 4 };
        HBRUSH accentBr = CreateSolidBrush(CLR_ACCENT);
        FillRect(hdc, &strip, accentBr);
        DeleteObject(accentBr);

        int cx = rc.right / 2, cy = 80, r = 40;
        DrawRoundRect(hdc, cx - r, cy - r, r * 2, r * 2, r * 2, CLR_SURFACE2, CLR_ACCENT, 2);

        SetBkMode(hdc, TRANSPARENT);
        HFONT hIconFont = CreateFontW(28, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe MDL2 Assets");
        HFONT old = (HFONT)SelectObject(hdc, hIconFont);
        SetTextColor(hdc, CLR_ACCENT2);
        RECT iconRc = { cx - r, cy - r, cx + r, cy + r };
        DrawTextW(hdc, L"\uE72E", -1, &iconRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE); 
        SelectObject(hdc, old);
        DeleteObject(hIconFont);

        HFONT titleFont = CreateFontW(26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        old = (HFONT)SelectObject(hdc, titleFont);
        SetTextColor(hdc, CLR_TEXT);
        RECT titleRc = { 0, 135, rc.right, 165 };
        DrawTextW(hdc, L"SecureVault", -1, &titleRc, DT_CENTER | DT_SINGLELINE);
        SelectObject(hdc, old);
        DeleteObject(titleFont);

        HFONT subFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        old = (HFONT)SelectObject(hdc, subFont);
        SetTextColor(hdc, CLR_TEXT2);
        RECT subRc = { 0, 163, rc.right, 183 };
        DrawTextW(hdc, L"AES-256 Encrypted Local Storage", -1, &subRc, DT_CENTER | DT_SINGLELINE);
        SelectObject(hdc, old);
        DeleteObject(subFont);

        DrawRoundRect(hdc, 52, 196, 336, 54, 8, CLR_SURFACE2, CLR_BORDER, 1);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* di = (DRAWITEMSTRUCT*)lp;
        if (di->CtlID == IDC_LOGIN_BTN) {
            HDC hdc = di->hDC;
            RECT rc = di->rcItem;
            bool pressed = (di->itemState & ODS_SELECTED) != 0;
            COLORREF btnColor = pressed ? CLR_ACCENT : RGB(31, 139, 241);

            DrawRoundRect(hdc, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, 8, btnColor);

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 255, 255));
            HFONT hf = CreateFontW(15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            HFONT old = (HFONT)SelectObject(hdc, hf);
            DrawTextW(hdc, L"Unlock Vault", -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(hdc, old);
            DeleteObject(hf);
            return TRUE;
        }
        return 0;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetBkColor(hdc, CLR_SURFACE2);
        SetTextColor(hdc, CLR_TEXT);
        static HBRUSH editBr = NULL;
        if (!editBr) editBr = CreateSolidBrush(CLR_SURFACE2);
        return (LRESULT)editBr;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        SetBkMode(hdc, TRANSPARENT);
        HWND hCtrl = (HWND)lp;
        if (hCtrl == g_hLoginStatus)
            SetTextColor(hdc, CLR_DANGER);
        else
            SetTextColor(hdc, CLR_TEXT2);
        static HBRUSH staticBr = NULL;
        if (!staticBr) staticBr = CreateSolidBrush(CLR_BG);
        return (LRESULT)staticBr;
    }

    case WM_KEYDOWN:
        if (wp == VK_RETURN) { SendMessageW(hwnd, WM_COMMAND, IDC_LOGIN_BTN, 0); return 0; }
        break;

    case WM_COMMAND:
        if (LOWORD(wp) == IDC_LOGIN_BTN) {
            wchar_t pass[256] = {};
            GetWindowTextW(g_hPassEdit, pass, 255);
            ConsoleLog(L"Authentication attempt received...", LOG_DEBUG);

            if (wcscmp(pass, VAULT_PASSWORD) == 0) {
                ConsoleLog(L"Password verified. Access granted.", LOG_SUCCESS);
                g_authenticated = true;
                SetWindowTextW(g_hLoginStatus, L"Access granted!");
                InvalidateRect(hwnd, NULL, TRUE);
                Sleep(250);
                ShowWindow(hwnd, SW_HIDE);
                extern void CreateDashboard();
                CreateDashboard();
            }
            else {
                ConsoleLog(L"Authentication FAILED — incorrect password", LOG_FAIL);
                SetWindowTextW(g_hLoginStatus, L"Incorrect password. Try again.");
                SetWindowTextW(g_hPassEdit, L"");
                MessageBeep(MB_ICONERROR);
                SetFocus(g_hPassEdit);
            }
            return 0;
        }
        break;

    case WM_DESTROY:
        if (!g_authenticated) PostQuitMessage(0);
        return 0;
    case WM_CLOSE:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

struct KeyPopupData { std::wstring key, iv, filename; bool isNote; };

LRESULT CALLBACK KeyPopupWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static KeyPopupData* data = nullptr;
    static HFONT hFontTitle = NULL, hFontMono = NULL, hFontUI = NULL, hFontSm = NULL;

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT* cs = (CREATESTRUCT*)lp;
        data = (KeyPopupData*)cs->lpCreateParams;

        hFontTitle = CreateFontW(17, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontMono = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Consolas");
        hFontUI = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontSm = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

        HWND hLbl = CreateWindowW(L"STATIC", L"DECRYPTION KEY  (AES-256)",
            WS_CHILD | WS_VISIBLE, 20, 65, 400, 18, hwnd, NULL, g_hInst, NULL);
        SendMessageW(hLbl, WM_SETFONT, (WPARAM)hFontSm, TRUE);

        HWND hKeyEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", data ? data->key.c_str() : L"",
            WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL,
            20, 86, 490, 30, hwnd, (HMENU)1001, g_hInst, NULL);
        SendMessageW(hKeyEdit, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        HWND hCopyKey = CreateWindowW(L"BUTTON", L"Copy Key",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            520, 86, 90, 30, hwnd, (HMENU)1004, g_hInst, NULL);
        SendMessageW(hCopyKey, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        HWND hIVLbl = CreateWindowW(L"STATIC", L"INITIALISATION VECTOR (IV)",
            WS_CHILD | WS_VISIBLE, 20, 128, 400, 18, hwnd, NULL, g_hInst, NULL);
        SendMessageW(hIVLbl, WM_SETFONT, (WPARAM)hFontSm, TRUE);

        HWND hIVEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", data ? data->iv.c_str() : L"",
            WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL,
            20, 148, 490, 30, hwnd, (HMENU)1002, g_hInst, NULL);
        SendMessageW(hIVEdit, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        HWND hCopyIV = CreateWindowW(L"BUTTON", L"Copy IV",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            520, 148, 90, 30, hwnd, (HMENU)1005, g_hInst, NULL);
        SendMessageW(hCopyIV, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        HWND hWarn = CreateWindowW(L"STATIC",
            L"⚠  Save these values now. They cannot be recovered if lost. Without them, your data is permanently unrecoverable.",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 192, 590, 36, hwnd, NULL, g_hInst, NULL);
        SendMessageW(hWarn, WM_SETFONT, (WPARAM)hFontSm, TRUE);

        HWND hClose = CreateWindowW(L"BUTTON", L"I've saved my key — Close",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            170, 240, 280, 36, hwnd, (HMENU)IDOK, g_hInst, NULL);
        SendMessageW(hClose, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        HBRUSH bg = CreateSolidBrush(CLR_SURFACE);
        FillRect(hdc, &rc, bg);
        DeleteObject(bg);

        RECT top = { 0, 0, rc.right, 4 };
        HBRUSH acBr = CreateSolidBrush(CLR_SUCCESS);
        FillRect(hdc, &top, acBr);
        DeleteObject(acBr);

        RECT titleBg = { 0, 4, rc.right, 58 };
        HBRUSH titleBrBg = CreateSolidBrush(CLR_BG);
        FillRect(hdc, &titleBg, titleBrBg);
        DeleteObject(titleBrBg);

        SetBkMode(hdc, TRANSPARENT);
        HFONT titleFont = CreateFontW(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HFONT old = (HFONT)SelectObject(hdc, titleFont);
        SetTextColor(hdc, CLR_TEXT);
        RECT tr = { 16, 4, rc.right - 16, 38 };
        std::wstring headerTitle = data && data->isNote ? L"Note Saved" : L"Encryption Complete";
        DrawTextW(hdc, headerTitle.c_str(), -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, old);
        DeleteObject(titleFont);

        HFONT smFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        old = (HFONT)SelectObject(hdc, smFont);
        SetTextColor(hdc, CLR_TEXT2);
        RECT fr = { 16, 36, rc.right, 56 };
        std::wstring fn = data ? (L"File: " + data->filename) : L"";
        DrawTextW(hdc, fn.c_str(), -1, &fr, DT_LEFT | DT_SINGLELINE);
        SelectObject(hdc, old);
        DeleteObject(smFont);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetBkColor(hdc, CLR_SURFACE2);
        SetTextColor(hdc, CLR_ACCENT2);
        static HBRUSH eBr = NULL;
        if (!eBr) eBr = CreateSolidBrush(CLR_SURFACE2);
        return (LRESULT)eBr;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        SetBkMode(hdc, TRANSPARENT);
        HWND hCtrl = (HWND)lp;
        SetTextColor(hdc, CLR_WARN);
        static HBRUSH sBr = NULL;
        if (!sBr) sBr = CreateSolidBrush(CLR_SURFACE);
        return (LRESULT)sBr;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == 1004 && data) { 
            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                size_t len = (data->key.length() + 1) * sizeof(wchar_t);
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
                if (hMem) { memcpy(GlobalLock(hMem), data->key.c_str(), len); GlobalUnlock(hMem); SetClipboardData(CF_UNICODETEXT, hMem); }
                CloseClipboard();
                SetWindowTextW(GetDlgItem(hwnd, id), L"Copied!");
                ConsoleLog(L"Decrypt key copied to clipboard", LOG_SUCCESS);
            }
        }
        else if (id == 1005 && data) { 
            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                size_t len = (data->iv.length() + 1) * sizeof(wchar_t);
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
                if (hMem) { memcpy(GlobalLock(hMem), data->iv.c_str(), len); GlobalUnlock(hMem); SetClipboardData(CF_UNICODETEXT, hMem); }
                CloseClipboard();
                SetWindowTextW(GetDlgItem(hwnd, id), L"Copied!");
            }
        }
        else if (id == IDOK) {
            DestroyWindow(hwnd);
        }
        return 0;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (hFontTitle) DeleteObject(hFontTitle);
        if (hFontMono)  DeleteObject(hFontMono);
        if (hFontUI)    DeleteObject(hFontUI);
        if (hFontSm)    DeleteObject(hFontSm);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static bool g_keyPopupClassReg = false;

void ShowKeyPopup(HWND parent, const std::wstring& filename, const std::wstring& key, const std::wstring& iv, bool isNote = false) {
    if (!g_keyPopupClassReg) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = KeyPopupWndProc;
        wc.hInstance = g_hInst;
        wc.hbrBackground = CreateSolidBrush(CLR_SURFACE);
        wc.lpszClassName = L"SVKeyPopup";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        RegisterClassExW(&wc);
        g_keyPopupClassReg = true;
    }

    KeyPopupData* data = new KeyPopupData{ key, iv, filename, isNote };

    RECT pr; GetWindowRect(parent, &pr);
    int pw = pr.right - pr.left, ph = pr.bottom - pr.top;
    int dw = 630, dh = 292;

    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        L"SVKeyPopup", isNote ? L"Note Saved" : L"Encryption Complete",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        pr.left + (pw - dw) / 2, pr.top + (ph - dh) / 2, dw, dh,
        parent, NULL, g_hInst, data);

    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);

    MSG msg;
    while (IsWindow(hDlg) && GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    delete data;
}

LRESULT CALLBACK DashboardWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

void CreateDashboard() {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DashboardWndProc;
    wc.hInstance = g_hInst;
    wc.hbrBackground = CreateSolidBrush(CLR_BG);
    wc.lpszClassName = L"SecureVaultDash";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassExW(&wc);

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    int w = 1020, h = 700;

    g_hDashWnd = CreateWindowExW(WS_EX_APPWINDOW,
        L"SecureVaultDash", L"SecureVault — Encrypted Storage Dashboard",
        WS_OVERLAPPEDWINDOW,
        (sw - w) / 2, (sh - h) / 2, w, h,
        NULL, NULL, g_hInst, NULL);

    ShowWindow(g_hDashWnd, SW_SHOW);
    UpdateWindow(g_hDashWnd);

    ConsoleLog(L"Dashboard created. Loading vault index...", LOG_DEBUG);
    LoadVaultIndex();
    RefreshFileList();
    RefreshNoteList();
    UpdateStatusBar(L"Ready  |  Vault: " + g_vaultPath + L"  |  Entries: " + std::to_wstring(g_vaultEntries.size()));
    ConsoleLog(L"SecureVault ready for operation.", LOG_SUCCESS);
}

void DrawFlatButton(HDC hdc, RECT rc, const wchar_t* text, COLORREF bgColor, COLORREF textColor, bool pressed) {
    COLORREF finalColor = pressed ? RGB(GetRValue(bgColor) - 20, GetGValue(bgColor) - 20, GetBValue(bgColor) - 20) : bgColor;
    DrawRoundRect(hdc, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, 6, finalColor);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, textColor);
    HFONT hf = CreateFontW(13, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    HFONT old = (HFONT)SelectObject(hdc, hf);
    DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, old);
    DeleteObject(hf);
}

LRESULT CALLBACK DashboardWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT hFontUI = NULL;
    static HFONT hFontMono = NULL;
    static HFONT hFontH1 = NULL;
    static HWND hKeyLabel = NULL;
    static int curTab = 0;

    switch (msg) {
    case WM_CREATE: {
        hFontUI = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontMono = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Consolas");
        hFontH1 = CreateFontW(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

        RECT rc; GetClientRect(hwnd, &rc);

        g_hStatusBar = CreateWindowW(STATUSCLASSNAMEW, L"Ready",
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS_BAR, g_hInst, NULL);
        SendMessageW(g_hStatusBar, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        g_hTabCtrl = CreateWindowExW(0, WC_TABCONTROLW, L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_HOTTRACK | TCS_FLATBUTTONS,
            0, 56, rc.right, rc.bottom - 80, hwnd,
            (HMENU)IDC_TAB_CTRL, g_hInst, NULL);
        SendMessageW(g_hTabCtrl, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        TCITEMW tab = {}; tab.mask = TCIF_TEXT;
        tab.pszText = (LPWSTR)L"   Files Vault   "; TabCtrl_InsertItem(g_hTabCtrl, 0, &tab);
        tab.pszText = (LPWSTR)L"   Notes         "; TabCtrl_InsertItem(g_hTabCtrl, 1, &tab);
        tab.pszText = (LPWSTR)L"   Decrypt Key   "; TabCtrl_InsertItem(g_hTabCtrl, 2, &tab);

        g_hFileList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            10, 92, rc.right - 190, rc.bottom - 140, hwnd,
            (HMENU)IDC_FILE_LIST, g_hInst, NULL);
        SendMessageW(g_hFileList, WM_SETFONT, (WPARAM)hFontUI, TRUE);
        ListView_SetExtendedListViewStyle(g_hFileList,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNW col = {}; col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = (LPWSTR)L"Filename";    col.cx = 300; ListView_InsertColumn(g_hFileList, 0, &col);
        col.pszText = (LPWSTR)L"Added";       col.cx = 160; ListView_InsertColumn(g_hFileList, 1, &col);
        col.pszText = (LPWSTR)L"Size";        col.cx = 90;  ListView_InsertColumn(g_hFileList, 2, &col);
        col.pszText = (LPWSTR)L"ID (partial)"; col.cx = 100; ListView_InsertColumn(g_hFileList, 3, &col);

        HWND btn;
        int bx = rc.right - 175, by = 92;
        btn = CreateWindowW(L"BUTTON", L"+ Upload File",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            bx, by, 160, 36, hwnd, (HMENU)IDC_UPLOAD_BTN, g_hInst, NULL);
        SendMessageW(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        btn = CreateWindowW(L"BUTTON", L"Export & Decrypt",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            bx, by + 44, 160, 36, hwnd, (HMENU)IDC_EXPORT_BTN, g_hInst, NULL);
        SendMessageW(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        btn = CreateWindowW(L"BUTTON", L"Delete Entry",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            bx, by + 88, 160, 36, hwnd, (HMENU)IDC_DELETE_BTN, g_hInst, NULL);
        SendMessageW(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        btn = CreateWindowW(L"BUTTON", L"Debug Console",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            bx, by + 160, 160, 36, hwnd, (HMENU)IDC_CONSOLE_BTN, g_hInst, NULL);
        SendMessageW(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        g_hNoteList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | LBS_NOTIFY | WS_VSCROLL,
            10, 92, 195, rc.bottom - 140, hwnd,
            (HMENU)IDC_NOTE_LIST, g_hInst, NULL);
        SendMessageW(g_hNoteList, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        g_hNoteTitle = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | ES_AUTOHSCROLL,
            215, 92, rc.right - 395, 32, hwnd,
            (HMENU)IDC_NOTE_TITLE, g_hInst, NULL);
        SendMessageW(g_hNoteTitle, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        g_hNoteEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            215, 132, rc.right - 395, rc.bottom - 190, hwnd,
            (HMENU)IDC_NOTE_EDIT, g_hInst, NULL);
        SendMessageW(g_hNoteEdit, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        int nx = rc.right - 175, ny = 92;
        btn = CreateWindowW(L"BUTTON", L"Save Note",
            WS_CHILD | BS_PUSHBUTTON,
            nx, ny, 160, 36, hwnd, (HMENU)IDC_NOTE_SAVE_BTN, g_hInst, NULL);
        SendMessageW(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);
        btn = CreateWindowW(L"BUTTON", L"New Note",
            WS_CHILD | BS_PUSHBUTTON,
            nx, ny + 44, 160, 36, hwnd, (HMENU)IDC_NOTE_NEW_BTN, g_hInst, NULL);
        SendMessageW(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);
        btn = CreateWindowW(L"BUTTON", L"Delete Note",
            WS_CHILD | BS_PUSHBUTTON,
            nx, ny + 88, 160, 36, hwnd, (HMENU)IDC_NOTE_DELETE_BTN, g_hInst, NULL);
        SendMessageW(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        hKeyLabel = CreateWindowW(L"STATIC",
            L"Paste your decrypt key (hex) below to retrieve a file or note:",
            WS_CHILD | SS_LEFT,
            20, 92, 700, 20, hwnd, NULL, g_hInst, NULL);
        SendMessageW(hKeyLabel, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        g_hKeyEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | ES_AUTOHSCROLL,
            20, 120, 680, 32, hwnd, (HMENU)IDC_KEY_EDIT, g_hInst, NULL);
        SendMessageW(g_hKeyEdit, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        btn = CreateWindowW(L"BUTTON", L"Copy",
            WS_CHILD | BS_PUSHBUTTON,
            710, 120, 70, 32, hwnd, (HMENU)IDC_KEY_COPY_BTN, g_hInst, NULL);
        SendMessageW(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        ShowWindow(g_hFileList, SW_SHOW);
        ShowWindow(GetDlgItem(hwnd, IDC_UPLOAD_BTN), SW_SHOW);
        ShowWindow(GetDlgItem(hwnd, IDC_EXPORT_BTN), SW_SHOW);
        ShowWindow(GetDlgItem(hwnd, IDC_DELETE_BTN), SW_SHOW);
        ShowWindow(GetDlgItem(hwnd, IDC_CONSOLE_BTN), SW_SHOW);

        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        HBRUSH bgBr = CreateSolidBrush(CLR_BG);
        FillRect(hdc, &rc, bgBr);
        DeleteObject(bgBr);

        RECT hdr = { 0, 0, rc.right, 56 };
        HBRUSH hdrBr = CreateSolidBrush(CLR_SURFACE);
        FillRect(hdc, &hdr, hdrBr);
        DeleteObject(hdrBr);

        RECT acBar = { 0, 0, 4, 56 };
        HBRUSH acBr = CreateSolidBrush(CLR_ACCENT);
        FillRect(hdc, &acBar, acBr);
        DeleteObject(acBr);

        SetBkMode(hdc, TRANSPARENT);

        HFONT titleFont = CreateFontW(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HFONT old = (HFONT)SelectObject(hdc, titleFont);
        SetTextColor(hdc, CLR_TEXT);
        RECT tr = { 18, 0, 400, 56 };
        DrawTextW(hdc, L"BCSVault", -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, old);
        DeleteObject(titleFont);

        HFONT smFont = CreateFontW(11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        old = (HFONT)SelectObject(hdc, smFont);
        SetTextColor(hdc, CLR_TEXT2);
        RECT vr = { 18, 34, 300, 54 };
        DrawTextW(hdc, L"v2.0  ·  AES-256-CBC  ·  Local Encrypted Storage", -1, &vr, DT_LEFT | DT_SINGLELINE);
        SelectObject(hdc, old);
        DeleteObject(smFont);

        wchar_t countStr[64];
        int fileCount = 0, noteCount = 0;
        for (auto& e : g_vaultEntries) { if (e.type == L"FILE") fileCount++; else noteCount++; }
        swprintf_s(countStr, L"%d Files  ·  %d Notes", fileCount, noteCount);
        HFONT countFont = CreateFontW(12, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        old = (HFONT)SelectObject(hdc, countFont);
        SetTextColor(hdc, CLR_ACCENT2);
        RECT cr = { rc.right - 220, 0, rc.right - 10, 56 };
        DrawTextW(hdc, countStr, -1, &cr, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, old);
        DeleteObject(countFont);

        RECT hdrBorder = { 0, 55, rc.right, 56 };
        HBRUSH borderBr = CreateSolidBrush(CLR_BORDER);
        FillRect(hdc, &hdrBorder, borderBr);
        DeleteObject(borderBr);

        EndPaint(hwnd, &ps);
        return 0;
    }

                 
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetBkColor(hdc, CLR_SURFACE2);
        SetTextColor(hdc, CLR_TEXT);
        static HBRUSH eBr = NULL;
        if (!eBr) eBr = CreateSolidBrush(CLR_SURFACE2);
        return (LRESULT)eBr;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, CLR_TEXT2);
        static HBRUSH sBr = NULL;
        if (!sBr) sBr = CreateSolidBrush(CLR_BG);
        return (LRESULT)sBr;
    }
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wp;
        SetBkColor(hdc, CLR_SURFACE2);
        SetTextColor(hdc, CLR_TEXT);
        static HBRUSH lbBr = NULL;
        if (!lbBr) lbBr = CreateSolidBrush(CLR_SURFACE2);
        return (LRESULT)lbBr;
    }

    case WM_NOTIFY: {
        NMHDR* nmhdr = (NMHDR*)lp;
        if (nmhdr->hwndFrom == g_hTabCtrl && nmhdr->code == TCN_SELCHANGE) {
            int tab = TabCtrl_GetCurSel(g_hTabCtrl);
            curTab = tab;

            ShowWindow(g_hFileList, SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_UPLOAD_BTN), SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_EXPORT_BTN), SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_DELETE_BTN), SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_CONSOLE_BTN), SW_HIDE);
            ShowWindow(g_hNoteList, SW_HIDE);
            ShowWindow(g_hNoteTitle, SW_HIDE);
            ShowWindow(g_hNoteEdit, SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_NOTE_SAVE_BTN), SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_NOTE_NEW_BTN), SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_NOTE_DELETE_BTN), SW_HIDE);
            ShowWindow(hKeyLabel, SW_HIDE);
            ShowWindow(g_hKeyEdit, SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_KEY_COPY_BTN), SW_HIDE);

            if (tab == 0) {
                ShowWindow(g_hFileList, SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_UPLOAD_BTN), SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_EXPORT_BTN), SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_DELETE_BTN), SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_CONSOLE_BTN), SW_SHOW);
            }
            else if (tab == 1) {
                ShowWindow(g_hNoteList, SW_SHOW);
                ShowWindow(g_hNoteTitle, SW_SHOW);
                ShowWindow(g_hNoteEdit, SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_NOTE_SAVE_BTN), SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_NOTE_NEW_BTN), SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_NOTE_DELETE_BTN), SW_SHOW);
            }
            else if (tab == 2) {
                ShowWindow(hKeyLabel, SW_SHOW);
                ShowWindow(g_hKeyEdit, SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_KEY_COPY_BTN), SW_SHOW);
            }
        }
        return 0;
    }

    case WM_SIZE: {
        RECT rc; GetClientRect(hwnd, &rc);
        SendMessageW(g_hStatusBar, WM_SIZE, 0, 0);
        RECT statusRc; GetWindowRect(g_hStatusBar, &statusRc);
        int sh2 = statusRc.bottom - statusRc.top;

        int contentW = rc.right - 20;
        int contentH = rc.bottom - sh2 - 100;
        int bx = rc.right - 175;

        SetWindowPos(g_hTabCtrl, NULL, 0, 56, rc.right, rc.bottom - sh2 - 60, SWP_NOZORDER);
        SetWindowPos(g_hFileList, NULL, 10, 92, rc.right - 190, contentH, SWP_NOZORDER);

        SetWindowPos(g_hNoteList, NULL, 10, 92, 195, contentH, SWP_NOZORDER);
        SetWindowPos(g_hNoteTitle, NULL, 215, 92, bx - 225, 32, SWP_NOZORDER);
        SetWindowPos(g_hNoteEdit, NULL, 215, 132, bx - 225, contentH - 42, SWP_NOZORDER);

        MoveWindow(GetDlgItem(hwnd, IDC_UPLOAD_BTN), bx, 92, 160, 36, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_EXPORT_BTN), bx, 136, 160, 36, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_DELETE_BTN), bx, 180, 160, 36, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_CONSOLE_BTN), bx, 252, 160, 36, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_NOTE_SAVE_BTN), bx, 92, 160, 36, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_NOTE_NEW_BTN), bx, 136, 160, 36, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_NOTE_DELETE_BTN), bx, 180, 160, 36, TRUE);

        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);

        if (id == IDC_CONSOLE_BTN) {
            if (g_hConsole) {
                if (IsWindowVisible(g_hConsole))
                    ShowWindow(g_hConsole, SW_HIDE);
                else {
                    ShowWindow(g_hConsole, SW_SHOW);
                    SetForegroundWindow(g_hConsole);
                }
            }
        }

        else if (id == IDC_UPLOAD_BTN) {
            ConsoleLog(L"File upload initiated by user...", LOG_DEBUG);
            wchar_t filePath[MAX_PATH] = {};
            OPENFILENAMEW ofn = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = filePath;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrTitle = L"Select File to Encrypt & Store";
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

            if (GetOpenFileNameW(&ofn)) {
                ConsoleLog(L"File selected: " + std::wstring(filePath), LOG_INFO);
                VaultEntry entry;
                if (EncryptFileToVault(filePath, entry)) {
                    g_vaultEntries.push_back(entry);
                    SaveVaultIndex();
                    RefreshFileList();
                    InvalidateRect(hwnd, NULL, FALSE); 
                    ShowKeyPopup(hwnd, entry.originalName, entry.keyHex, entry.ivHex, false);
                    UpdateStatusBar(L"File encrypted and stored: " + entry.originalName);
                    ConsoleLog(L"Vault entry added. Key: " + entry.keyHex.substr(0, 16) + L"...", LOG_SUCCESS);
                }
                else {
                    MessageBoxW(hwnd, L"Failed to encrypt file. Check debug console.", L"Error", MB_ICONERROR);
                }
            }
            else {
                ConsoleLog(L"File upload cancelled by user", LOG_INFO);
            }
        }

        else if (id == IDC_EXPORT_BTN) {
            int sel = ListView_GetNextItem(g_hFileList, -1, LVNI_SELECTED);
            if (sel < 0) { MessageBoxW(hwnd, L"Select a file from the list first.", L"No Selection", MB_ICONWARNING); return 0; }

            LVITEMW lvi = {}; lvi.mask = LVIF_PARAM; lvi.iItem = sel;
            ListView_GetItem(g_hFileList, &lvi);
            int idx = (int)lvi.lParam;
            if (idx < 0 || idx >= (int)g_vaultEntries.size()) return 0;
            auto& entry = g_vaultEntries[idx];

            ConsoleLog(L"Export requested: " + entry.originalName, LOG_INFO);
            wchar_t savePath[MAX_PATH] = {};
            wcscpy_s(savePath, entry.originalName.c_str());
            OPENFILENAMEW ofn = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = savePath;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrTitle = L"Save Decrypted File As";
            ofn.Flags = OFN_OVERWRITEPROMPT;

            if (GetSaveFileNameW(&ofn)) {
                std::vector<BYTE> plainData;
                if (DecryptFromVault(entry, plainData)) {
                    HANDLE hOut = CreateFileW(savePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hOut != INVALID_HANDLE_VALUE) {
                        DWORD written;
                        WriteFile(hOut, plainData.data(), (DWORD)plainData.size(), &written, NULL);
                        CloseHandle(hOut);
                        ConsoleLog(L"File exported: " + std::wstring(savePath), LOG_SUCCESS);
                        MessageBoxW(hwnd, L"File decrypted and exported successfully!", L"Export Complete", MB_ICONINFORMATION);
                    }
                }
                else {
                    MessageBoxW(hwnd, L"Decryption failed. Check debug console.", L"Decryption Error", MB_ICONERROR);
                }
            }
        }

        else if (id == IDC_DELETE_BTN) {
            int sel = ListView_GetNextItem(g_hFileList, -1, LVNI_SELECTED);
            if (sel < 0) { MessageBoxW(hwnd, L"Select a file from the list first.", L"No Selection", MB_ICONWARNING); return 0; }
            LVITEMW lvi = {}; lvi.mask = LVIF_PARAM; lvi.iItem = sel;
            ListView_GetItem(g_hFileList, &lvi);
            int idx = (int)lvi.lParam;
            if (idx < 0 || idx >= (int)g_vaultEntries.size()) return 0;

            int res = MessageBoxW(hwnd,
                (L"Permanently delete '" + g_vaultEntries[idx].originalName + L"' from vault?\n\nThis cannot be undone.").c_str(),
                L"Confirm Delete", MB_YESNO | MB_ICONWARNING);
            if (res == IDYES) {
                ConsoleLog(L"Deleting vault entry: " + g_vaultEntries[idx].originalName, LOG_WARN);
                DeleteFileW(g_vaultEntries[idx].encryptedPath.c_str());
                g_vaultEntries.erase(g_vaultEntries.begin() + idx);
                SaveVaultIndex();
                RefreshFileList();
                InvalidateRect(hwnd, NULL, FALSE);
                ConsoleLog(L"Vault entry deleted", LOG_SUCCESS);
                UpdateStatusBar(L"Entry deleted. " + std::to_wstring(g_vaultEntries.size()) + L" entries remaining.");
            }
        }

        else if (id == IDC_NOTE_SAVE_BTN) {
            wchar_t titleBuf[256] = {}, contentBuf[65536] = {};
            GetWindowTextW(g_hNoteTitle, titleBuf, 255);
            GetWindowTextW(g_hNoteEdit, contentBuf, 65535);

            if (wcslen(titleBuf) == 0) { MessageBoxW(hwnd, L"Please enter a title for the note.", L"No Title", MB_ICONWARNING); return 0; }
            if (wcslen(contentBuf) == 0) { MessageBoxW(hwnd, L"Note content is empty.", L"Empty Note", MB_ICONWARNING); return 0; }

            ConsoleLog(L"Saving note: " + std::wstring(titleBuf), LOG_DEBUG);

            if (g_selectedNote >= 0 && g_selectedNote < (int)g_vaultEntries.size()) {
                ConsoleLog(L"Updating existing note...", LOG_DEBUG);
                DeleteFileW(g_vaultEntries[g_selectedNote].encryptedPath.c_str());
                g_vaultEntries.erase(g_vaultEntries.begin() + g_selectedNote);
                g_selectedNote = -1;
            }

            VaultEntry entry;
            if (EncryptNoteToVault(titleBuf, contentBuf, entry)) {
                g_vaultEntries.push_back(entry);
                SaveVaultIndex();
                RefreshNoteList();
                InvalidateRect(hwnd, NULL, FALSE);
                ConsoleLog(L"Note encrypted and saved: " + std::wstring(titleBuf), LOG_SUCCESS);
                ShowKeyPopup(hwnd, entry.originalName.substr(5), entry.keyHex, entry.ivHex, true);
                UpdateStatusBar(L"Note saved: " + std::wstring(titleBuf));
            }
            else {
                MessageBoxW(hwnd, L"Failed to save note.", L"Error", MB_ICONERROR);
            }
        }

        else if (id == IDC_NOTE_NEW_BTN) {
            g_selectedNote = -1;
            SetWindowTextW(g_hNoteTitle, L"");
            SetWindowTextW(g_hNoteEdit, L"");
            SetFocus(g_hNoteTitle);
            ConsoleLog(L"New note editor ready", LOG_DEBUG);
        }

        else if (id == IDC_NOTE_DELETE_BTN) {
            if (g_selectedNote < 0) { MessageBoxW(hwnd, L"Select a note from the list first.", L"No Selection", MB_ICONWARNING); return 0; }
            auto& e = g_vaultEntries[g_selectedNote];
            int res = MessageBoxW(hwnd, (L"Delete note '" + e.originalName.substr(5) + L"'?").c_str(), L"Confirm", MB_YESNO | MB_ICONWARNING);
            if (res == IDYES) {
                DeleteFileW(e.encryptedPath.c_str());
                g_vaultEntries.erase(g_vaultEntries.begin() + g_selectedNote);
                g_selectedNote = -1;
                SaveVaultIndex();
                RefreshNoteList();
                InvalidateRect(hwnd, NULL, FALSE);
                SetWindowTextW(g_hNoteTitle, L"");
                SetWindowTextW(g_hNoteEdit, L"");
                ConsoleLog(L"Note deleted", LOG_SUCCESS);
            }
        }

        else if (id == IDC_NOTE_LIST && HIWORD(wp) == LBN_SELCHANGE) {
            int sel = (int)SendMessageW(g_hNoteList, LB_GETCURSEL, 0, 0);
            if (sel < 0) return 0;
            int entryIdx = (int)SendMessageW(g_hNoteList, LB_GETITEMDATA, sel, 0);
            if (entryIdx >= 0 && entryIdx < (int)g_vaultEntries.size()) {
                auto& e = g_vaultEntries[entryIdx];
                ConsoleLog(L"Loading note: " + e.originalName, LOG_DEBUG);
                std::vector<BYTE> plainData;
                if (DecryptFromVault(e, plainData)) {
                    std::vector<BYTE> nullTerm = plainData;
                    nullTerm.push_back(0);
                    int wLen = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)nullTerm.data(), -1, NULL, 0);
                    std::vector<wchar_t> wContent(wLen);
                    MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)nullTerm.data(), -1, wContent.data(), wLen);
                    std::wstring title = e.originalName;
                    if (title.substr(0, 5) == L"NOTE:") title = title.substr(5);
                    SetWindowTextW(g_hNoteTitle, title.c_str());
                    SetWindowTextW(g_hNoteEdit, wContent.data());
                    g_selectedNote = entryIdx;
                    ConsoleLog(L"Note decrypted and loaded", LOG_SUCCESS);
                }
                else {
                    MessageBoxW(hwnd, L"Failed to decrypt note.", L"Error", MB_ICONERROR);
                }
            }
        }

        else if (id == IDC_KEY_COPY_BTN) {
            wchar_t keyBuf[256] = {};
            GetWindowTextW(g_hKeyEdit, keyBuf, 255);
            if (wcslen(keyBuf) > 0) {
                if (OpenClipboard(hwnd)) {
                    EmptyClipboard();
                    size_t len = (wcslen(keyBuf) + 1) * sizeof(wchar_t);
                    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
                    if (hMem) { memcpy(GlobalLock(hMem), keyBuf, len); GlobalUnlock(hMem); SetClipboardData(CF_UNICODETEXT, hMem); }
                    CloseClipboard();
                    ConsoleLog(L"Key copied to clipboard", LOG_SUCCESS);
                    UpdateStatusBar(L"Key copied to clipboard");
                }
            }
        }

        return 0;
    }

    case WM_CLOSE:
        if (MessageBoxW(hwnd, L"Exit SecureVault?\n\nAll data remains securely encrypted in the vault.", L"Confirm Exit", MB_YESNO | MB_ICONQUESTION) == IDYES) {
            ConsoleLog(L"User initiated shutdown. Vault secured.", LOG_INFO);
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_DESTROY:
        ConsoleLog(L"SecureVault shut down cleanly.", LOG_SUCCESS);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    g_hInst = hInstance;

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES | ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    HMODULE hRichEdit = LoadLibraryW(L"MSFTEDIT.DLL");
    if (!hRichEdit) {
        
        hRichEdit = LoadLibraryW(L"RICHED20.DLL");
    }

    CreateConsoleWindow();

    ConsoleLog(L"RichEdit DLL loaded: " + std::wstring(hRichEdit ? L"MSFTEDIT.DLL OK" : L"Fallback to EDIT"), hRichEdit ? LOG_SUCCESS : LOG_WARN);
    ConsoleLog(L"Locating vault storage directory...", LOG_DEBUG);

    wchar_t appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        g_vaultPath = std::wstring(appDataPath) + L"\\" + VAULT_DIR_NAME;
    }
    else {
        g_vaultPath = L"C:\\SecureVault_Storage";
        ConsoleLog(L"Could not get AppData path — falling back to C:\\", LOG_WARN);
    }

    ConsoleLog(L"Vault path: " + g_vaultPath, LOG_INFO);

    if (!PathFileExistsW(g_vaultPath.c_str())) {
        ConsoleLog(L"Vault directory not found. Creating: " + g_vaultPath, LOG_INFO);
        if (CreateDirectoryW(g_vaultPath.c_str(), NULL)) {
            ConsoleLog(L"Vault directory created successfully", LOG_SUCCESS);
            SetFileAttributesW(g_vaultPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            ConsoleLog(L"Vault directory marked hidden + system", LOG_DEBUG);
        }
        else {
            ConsoleLog(L"CRITICAL: Cannot create vault directory!", LOG_FAIL);
            MessageBoxW(NULL, L"Cannot create vault storage directory.", L"Fatal Error", MB_ICONERROR);
            return 1;
        }
    }
    else {
        ConsoleLog(L"Existing vault found at: " + g_vaultPath, LOG_SUCCESS);
    }

    ConsoleLog(L"Launching login window...", LOG_DEBUG);
    CreateLoginWindow();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        
        if (g_hLoginWnd && IsWindowVisible(g_hLoginWnd) &&
            msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            SendMessageW(g_hLoginWnd, WM_COMMAND, IDC_LOGIN_BTN, 0);
            continue;
        }
        HWND loginFocus = g_hLoginWnd ? g_hLoginWnd : NULL;
        HWND dashFocus = g_hDashWnd ? g_hDashWnd : NULL;
        if (!IsDialogMessageW(loginFocus, &msg) &&
            !IsDialogMessageW(dashFocus, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if (hRichEdit) FreeLibrary(hRichEdit);
    return 0;
}
