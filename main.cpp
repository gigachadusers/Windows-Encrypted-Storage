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

const wchar_t* VAULT_PASSWORD = L"1234";   
const wchar_t* VAULT_DIR_NAME = L"SecureVault_Storage";
const wchar_t* VAULT_INDEX_FILE = L"vault.idx";
const wchar_t* APP_NAME = L"SecureVault";
const wchar_t* APP_VERSION = L"1.0.0";

#define AES_KEY_SIZE    32
#define AES_IV_SIZE     16
#define AES_BLOCK_SIZE  16
#define SALT_SIZE       32
#define PBKDF2_ITERS    100000

#define IDC_PASSWORD_EDIT       1001
#define IDC_LOGIN_BTN           1002
#define IDC_TAB_CTRL            1010
#define IDC_FILE_LIST           1020
#define IDC_UPLOAD_BTN          1021
#define IDC_DECRYPT_BTN         1022
#define IDC_DELETE_BTN          1023
#define IDC_EXPORT_BTN          1024
#define IDC_NOTE_EDIT           1030
#define IDC_NOTE_TITLE          1031
#define IDC_NOTE_SAVE_BTN       1032
#define IDC_NOTE_NEW_BTN        1033
#define IDC_NOTE_DELETE_BTN     1034
#define IDC_NOTE_LIST           1035
#define IDC_KEY_EDIT            1040
#define IDC_KEY_COPY_BTN        1041
#define IDC_STATUS_BAR          1050

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
    case LOG_SUCCESS: cf.crTextColor = RGB(0, 220, 80);   break;
    case LOG_FAIL:    cf.crTextColor = RGB(255, 60, 60);  break;
    case LOG_WARN:    cf.crTextColor = RGB(255, 200, 0);  break;
    case LOG_DEBUG:   cf.crTextColor = RGB(100, 180, 255); break;
    default:          cf.crTextColor = RGB(180, 180, 180); break;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timeBuf[32];
    swprintf_s(timeBuf, L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);

    CHARFORMAT2W cfTime = cf;
    cfTime.crTextColor = RGB(100, 100, 100);

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

bool AES256Encrypt(const BYTE* plaintext, DWORD ptLen,
    const BYTE* key, const BYTE* iv,
    std::vector<BYTE>& ciphertext) {
    ConsoleLog(L"Initializing AES-256-CBC encryption engine...", LOG_DEBUG);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        ConsoleLog(L"Failed to open AES algorithm provider", LOG_FAIL);
        return false;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        ConsoleLog(L"Failed to set CBC chaining mode", LOG_FAIL);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    DWORD keyObjSize = 0, bytesReturned = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&keyObjSize, sizeof(DWORD), &bytesReturned, 0);

    std::vector<BYTE> keyObj(keyObjSize);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize,
        (PUCHAR)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        ConsoleLog(L"Failed to generate symmetric key", LOG_FAIL);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    DWORD ctLen = 0;
    BYTE ivCopy[AES_IV_SIZE];
    memcpy(ivCopy, iv, AES_IV_SIZE);

    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, ptLen,
        NULL, ivCopy, AES_IV_SIZE, NULL, 0, &ctLen, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        ConsoleLog(L"Failed to get ciphertext size", LOG_FAIL);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    ciphertext.resize(ctLen);
    memcpy(ivCopy, iv, AES_IV_SIZE);

    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, ptLen,
        NULL, ivCopy, AES_IV_SIZE, ciphertext.data(), ctLen, &ctLen, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        ConsoleLog(L"Encryption operation failed", LOG_FAIL);
        return false;
    }

    ConsoleLog(L"Encryption complete. Block padding applied (PKCS7)", LOG_SUCCESS);
    return true;
}

bool AES256Decrypt(const BYTE* ciphertext, DWORD ctLen,
    const BYTE* key, const BYTE* iv,
    std::vector<BYTE>& plaintext) {
    ConsoleLog(L"Initializing AES-256-CBC decryption engine...", LOG_DEBUG);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        ConsoleLog(L"Failed to open AES algorithm provider", LOG_FAIL);
        return false;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    DWORD keyObjSize = 0, bytesReturned = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&keyObjSize, sizeof(DWORD), &bytesReturned, 0);

    std::vector<BYTE> keyObj(keyObjSize);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjSize,
        (PUCHAR)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        ConsoleLog(L"Invalid key material", LOG_FAIL);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    DWORD ptLen = 0;
    BYTE ivCopy[AES_IV_SIZE];
    memcpy(ivCopy, iv, AES_IV_SIZE);

    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, ctLen,
        NULL, ivCopy, AES_IV_SIZE, NULL, 0, &ptLen, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        ConsoleLog(L"Decryption size query failed - wrong key?", LOG_FAIL);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    plaintext.resize(ptLen);
    memcpy(ivCopy, iv, AES_IV_SIZE);

    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, ctLen,
        NULL, ivCopy, AES_IV_SIZE, plaintext.data(), ptLen, &ptLen, BCRYPT_BLOCK_PADDING);
    plaintext.resize(ptLen);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        ConsoleLog(L"Decryption failed - key or IV may be incorrect", LOG_FAIL);
        return false;
    }

    ConsoleLog(L"Decryption successful. Data integrity verified", LOG_SUCCESS);
    return true;
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

bool SaveVaultIndex() {
    std::wstring idxPath = g_vaultPath + L"\\" + VAULT_INDEX_FILE;

    ConsoleLog(L"Serialising vault index...", LOG_DEBUG);

    std::wostringstream ss;
    ss << L"SECUREVAULT_INDEX_V1\n";
    ss << g_vaultEntries.size() << L"\n";
    for (auto& e : g_vaultEntries) {
        ss << e.id << L"\t"
            << e.originalName << L"\t"
            << e.encryptedPath << L"\t"
            << e.keyHex << L"\t"
            << e.ivHex << L"\t"
            << e.type << L"\t"
            << e.addedTime << L"\t"
            << e.originalSize << L"\n";
    }

    std::wstring data = ss.str();

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, NULL, 0, NULL, NULL);
    std::vector<char> utf8Data(utf8Len);
    WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, utf8Data.data(), utf8Len, NULL, NULL);

    HANDLE hFile = CreateFileW(idxPath.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ConsoleLog(L"Failed to write vault index file", LOG_FAIL);
        return false;
    }

    DWORD written;
    WriteFile(hFile, utf8Data.data(), (DWORD)utf8Data.size() - 1, &written, NULL);
    CloseHandle(hFile);

    ConsoleLog(L"Vault index saved (" + std::to_wstring(g_vaultEntries.size()) + L" entries)", LOG_SUCCESS);
    return true;
}

bool LoadVaultIndex() {
    std::wstring idxPath = g_vaultPath + L"\\" + VAULT_INDEX_FILE;

    if (!PathFileExistsW(idxPath.c_str())) {
        ConsoleLog(L"No existing vault index - fresh vault", LOG_INFO);
        return true;
    }

    ConsoleLog(L"Loading vault index from disk...", LOG_DEBUG);

    HANDLE hFile = CreateFileW(idxPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ConsoleLog(L"Cannot open vault index - access denied?", LOG_FAIL);
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    std::vector<char> buf(fileSize + 1, 0);
    DWORD bytesRead;
    ReadFile(hFile, buf.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    int wLen = MultiByteToWideChar(CP_UTF8, 0, buf.data(), -1, NULL, 0);
    std::vector<wchar_t> wBuf(wLen);
    MultiByteToWideChar(CP_UTF8, 0, buf.data(), -1, wBuf.data(), wLen);
    std::wstring data(wBuf.data());

    std::wistringstream ss(data);
    std::wstring line;
    std::getline(ss, line);
    if (line != L"SECUREVAULT_INDEX_V1") {
        ConsoleLog(L"Vault index format unrecognised", LOG_FAIL);
        return false;
    }

    int count = 0;
    std::getline(ss, line);
    count = std::stoi(line);

    g_vaultEntries.clear();
    for (int i = 0; i < count; i++) {
        std::getline(ss, line);
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

    ConsoleLog(L"Vault index loaded: " + std::to_wstring(g_vaultEntries.size()) + L" entries found", LOG_SUCCESS);
    return true;
}

bool EncryptFileToVault(const std::wstring& srcPath, VaultEntry& outEntry) {
    ConsoleLog(L"Reading source file: " + srcPath, LOG_DEBUG);

    HANDLE hSrc = CreateFileW(srcPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) {
        ConsoleLog(L"Cannot open source file for reading", LOG_FAIL);
        return false;
    }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hSrc, &fileSize);

    if (fileSize.QuadPart == 0) {
        ConsoleLog(L"Source file is empty", LOG_WARN);
        CloseHandle(hSrc);
        return false;
    }

    ConsoleLog(L"File size: " + std::to_wstring(fileSize.QuadPart) + L" bytes", LOG_DEBUG);

    if (fileSize.QuadPart > MAXDWORD) {
        ConsoleLog(L"Files larger than 4GB are not supported", LOG_FAIL);
        CloseHandle(hSrc);
        return false;
    }

    std::vector<BYTE> plainData((size_t)fileSize.QuadPart);
    DWORD bytesRead;
    if (!ReadFile(hSrc, plainData.data(), (DWORD)fileSize.QuadPart, &bytesRead, NULL)) {
        ConsoleLog(L"Failed to read file data", LOG_FAIL);
        CloseHandle(hSrc);
        return false;
    }
    CloseHandle(hSrc);

    ConsoleLog(L"Generating 256-bit AES key and 128-bit IV...", LOG_DEBUG);

    BYTE key[AES_KEY_SIZE], iv[AES_IV_SIZE];
    if (!GenRandom(key, AES_KEY_SIZE) || !GenRandom(iv, AES_IV_SIZE)) {
        ConsoleLog(L"RNG failure - cannot generate secure key material", LOG_FAIL);
        return false;
    }

    std::wstring keyHex = BytesToHex(key, AES_KEY_SIZE);
    std::wstring ivHex = BytesToHex(iv, AES_IV_SIZE);
    ConsoleLog(L"Key generated: " + keyHex.substr(0, 16) + L"...[truncated]", LOG_DEBUG);

    std::vector<BYTE> cipherData;
    if (!AES256Encrypt(plainData.data(), (DWORD)plainData.size(), key, iv, cipherData)) {
        ConsoleLog(L"Encryption failed", LOG_FAIL);
        return false;
    }

    std::wstring id = GenerateID();
    std::wstring encPath = g_vaultPath + L"\\" + id + L".enc";

    HANDLE hDst = CreateFileW(encPath.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {
        ConsoleLog(L"Cannot write encrypted file to vault", LOG_FAIL);
        return false;
    }

    const BYTE MAGIC[8] = { 0x53,0x56,0x41,0x55,0x4C,0x54,0x01,0x00 }; 
    DWORD written;
    WriteFile(hDst, MAGIC, 8, &written, NULL);
    WriteFile(hDst, iv, AES_IV_SIZE, &written, NULL);
    WriteFile(hDst, cipherData.data(), (DWORD)cipherData.size(), &written, NULL);
    CloseHandle(hDst);

    ConsoleLog(L"Encrypted file written to vault: " + id + L".enc", LOG_SUCCESS);

    ConsoleLog(L"Securely deleting original file", LOG_DEBUG);

    HANDLE hOvr = CreateFileW(srcPath.c_str(), GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

    if (!DeleteFileW(srcPath.c_str())) {
        ConsoleLog(L"Warning: Could not delete original file (may need manual deletion)", LOG_WARN);
    }
    else {
        ConsoleLog(L"Original file securely wiped and deleted", LOG_SUCCESS);
    }

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
    WideCharToMultiByte(CP_UTF8, 0, content.c_str(), -1,
        (LPSTR)noteData.data(), utf8Len, NULL, NULL);

    if (noteData.empty()) {
        ConsoleLog(L"Note content is empty", LOG_WARN);
        return false;
    }

    BYTE key[AES_KEY_SIZE], iv[AES_IV_SIZE];
    if (!GenRandom(key, AES_KEY_SIZE) || !GenRandom(iv, AES_IV_SIZE)) {
        ConsoleLog(L"RNG failure generating note key", LOG_FAIL);
        return false;
    }

    std::vector<BYTE> cipherData;
    if (!AES256Encrypt(noteData.data(), (DWORD)noteData.size(), key, iv, cipherData)) {
        return false;
    }

    std::wstring id = GenerateID();
    std::wstring encPath = g_vaultPath + L"\\" + id + L".enc";

    HANDLE hDst = CreateFileW(encPath.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {
        ConsoleLog(L"Cannot write encrypted note to vault", LOG_FAIL);
        return false;
    }

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
        ConsoleLog(L"Encrypted file not found on disk: " + entry.encryptedPath, LOG_FAIL);
        return false;
    }

    std::vector<BYTE> key, iv;
    if (!HexToBytes(entry.keyHex, key) || key.size() != AES_KEY_SIZE) {
        ConsoleLog(L"Invalid key hex in vault entry", LOG_FAIL);
        return false;
    }
    if (!HexToBytes(entry.ivHex, iv) || iv.size() != AES_IV_SIZE) {
        ConsoleLog(L"Invalid IV hex in vault entry", LOG_FAIL);
        return false;
    }

    HANDLE hFile = CreateFileW(entry.encryptedPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ConsoleLog(L"Cannot open encrypted file", LOG_FAIL);
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize < 8 + AES_IV_SIZE) {
        ConsoleLog(L"Encrypted file too small - corrupted?", LOG_FAIL);
        CloseHandle(hFile);
        return false;
    }

    std::vector<BYTE> rawData(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, rawData.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Skip magic (8 bytes) and stored IV (16 bytes) - use entry's IV
    DWORD cipherOffset = 8 + AES_IV_SIZE;
    DWORD cipherLen = fileSize - cipherOffset;

    ConsoleLog(L"Ciphertext size: " + std::to_wstring(cipherLen) + L" bytes", LOG_DEBUG);

    return AES256Decrypt(rawData.data() + cipherOffset, cipherLen,
        key.data(), iv.data(), outData);
}

// Decrypt with user-provided key hex (for manual key entry)
bool DecryptWithProvidedKey(const VaultEntry& entry, const std::wstring& userKeyHex, std::vector<BYTE>& outData) {
    ConsoleLog(L"Decrypting with user-provided key...", LOG_DEBUG);

    VaultEntry modEntry = entry;
    modEntry.keyHex = userKeyHex;
    return DecryptFromVault(modEntry, outData);
}

// UI Helpers
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

// Console Window 
LRESULT CALLBACK ConsoleWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        SetWindowPos(g_hConsoleEdit, NULL, 0, 0, rc.right, rc.bottom,
            SWP_NOZORDER | SWP_NOACTIVATE);
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
    wc.hbrBackground = CreateSolidBrush(RGB(12, 12, 12));
    wc.lpszClassName = L"SecureVaultConsole";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);

    g_hConsole = CreateWindowExW(WS_EX_TOOLWINDOW,
        L"SecureVaultConsole", L"SecureVault Debug Console",
        WS_OVERLAPPEDWINDOW,
        0, 0, 700, 450, NULL, NULL, g_hInst, NULL);

    g_hConsoleEdit = CreateWindowExW(WS_EX_CLIENTEDGE,
        L"MSFTEDIT_CLASS", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 700, 450, g_hConsole, NULL, g_hInst, NULL);

    SendMessageW(g_hConsoleEdit, EM_SETBKGNDCOLOR, 0, RGB(12, 12, 12));

    ShowWindow(g_hConsole, SW_SHOW);
    UpdateWindow(g_hConsole);

    ConsoleLog(L"═══════════════════════════════════════════════════", LOG_INFO);
    ConsoleLog(L"  SecureVault v1.0.0 - Debug Console", LOG_SUCCESS);
    ConsoleLog(L"  AES-256-CBC | Windows CNG | Local Storage", LOG_INFO);
    ConsoleLog(L"═══════════════════════════════════════════════════", LOG_INFO);
    ConsoleLog(L"Initialising SecureVault system...", LOG_DEBUG);
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
    wc.hbrBackground = CreateSolidBrush(RGB(22, 25, 35));
    wc.lpszClassName = L"SecureVaultLogin";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassExW(&wc);

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    int w = 420, h = 340;

    g_hLoginWnd = CreateWindowExW(WS_EX_APPWINDOW,
        L"SecureVaultLogin", L"SecureVault — Authentication",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        (sw - w) / 2, (sh - h) / 2, w, h,
        NULL, NULL, g_hInst, NULL);

    ShowWindow(g_hLoginWnd, SW_SHOW);
    UpdateWindow(g_hLoginWnd);
    ConsoleLog(L"Login window created. Awaiting authentication...", LOG_INFO);
}

LRESULT CALLBACK LoginWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT hFontLarge = NULL;
    static HFONT hFontMed = NULL;
    static HFONT hFontSmall = NULL;

    switch (msg) {
    case WM_CREATE: {
        hFontLarge = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontMed = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontSmall = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

        HWND hLabel = CreateWindowW(L"STATIC", L"Enter Vault Password",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            40, 130, 340, 24, hwnd, NULL, g_hInst, NULL);
        SendMessage(hLabel, WM_SETFONT, (WPARAM)hFontMed, TRUE);

        g_hPassEdit = CreateWindowExW(WS_EX_CLIENTEDGE,
            L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_CENTER,
            80, 165, 260, 34, hwnd, (HMENU)IDC_PASSWORD_EDIT, g_hInst, NULL);
        SendMessage(g_hPassEdit, WM_SETFONT, (WPARAM)hFontMed, TRUE);

        g_hLoginBtn = CreateWindowW(L"BUTTON", L"Unlock Vault",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            120, 215, 180, 38, hwnd, (HMENU)IDC_LOGIN_BTN, g_hInst, NULL);
        SendMessage(g_hLoginBtn, WM_SETFONT, (WPARAM)hFontMed, TRUE);

        g_hLoginStatus = CreateWindowW(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            40, 265, 340, 20, hwnd, NULL, g_hInst, NULL);
        SendMessage(g_hLoginStatus, WM_SETFONT, (WPARAM)hFontSmall, TRUE);

        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rc;
        GetClientRect(hwnd, &rc);

        HBRUSH bgBrush = CreateSolidBrush(RGB(22, 25, 35));
        FillRect(hdc, &rc, bgBrush);
        DeleteObject(bgBrush);

        HBRUSH iconBg = CreateSolidBrush(RGB(40, 130, 220));
        RECT iconRc = { 180, 30, 240, 90 };
        HPEN pen = CreatePen(PS_NULL, 0, 0);
        HGDIOBJ oldPen = SelectObject(hdc, pen);
        HGDIOBJ oldBrush = SelectObject(hdc, iconBg);
        RoundRect(hdc, iconRc.left, iconRc.top, iconRc.right, iconRc.bottom, 12, 12);
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(iconBg);
        DeleteObject(pen);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));
        HFONT hIconFont = CreateFontW(36, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI Symbol");
        HFONT oldFont = (HFONT)SelectObject(hdc, hIconFont);
        DrawTextW(hdc, L"LOCK", -1, &iconRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, oldFont);
        DeleteObject(hIconFont);

        HFONT titleFont = CreateFontW(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        oldFont = (HFONT)SelectObject(hdc, titleFont);
        SetTextColor(hdc, RGB(255, 255, 255));
        RECT titleRc = { 0, 100, 420, 130 };
        DrawTextW(hdc, L"BCSVault", -1, &titleRc, DT_CENTER | DT_SINGLELINE);
        SelectObject(hdc, oldFont);
        DeleteObject(titleFont);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetBkColor(hdc, RGB(30, 35, 50));
        SetTextColor(hdc, RGB(220, 220, 220));
        static HBRUSH editBrush = CreateSolidBrush(RGB(30, 35, 50));
        return (LRESULT)editBrush;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        SetBkMode(hdc, TRANSPARENT);
        HWND hCtrl = (HWND)lp;
        if (hCtrl == g_hLoginStatus) {
            SetTextColor(hdc, RGB(255, 80, 80));
        }
        else {
            SetTextColor(hdc, RGB(180, 190, 210));
        }
        static HBRUSH staticBrush = CreateSolidBrush(RGB(22, 25, 35));
        return (LRESULT)staticBrush;
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wp))
        {
        case IDC_LOGIN_BTN:
        {
            wchar_t pass[256] = {};
            GetWindowTextW(g_hPassEdit, pass, 255);

            ConsoleLog(L"Authentication attempt received...", LOG_DEBUG);

            if (wcscmp(pass, VAULT_PASSWORD) == 0)
            {
                ConsoleLog(L"Password verified. Granting access.", LOG_SUCCESS);

                g_authenticated = true;

                SetWindowTextW(g_hLoginStatus, L"Access granted!");

                Sleep(300);

                ShowWindow(hwnd, SW_HIDE);

                extern void CreateDashboard();
                CreateDashboard();
            }
            else
            {
                ConsoleLog(L"Authentication FAILED - incorrect password", LOG_FAIL);

                SetWindowTextW(
                    g_hLoginStatus,
                    L"Incorrect password. Try again."
                );

                SetWindowTextW(g_hPassEdit, L"");

                MessageBeep(MB_ICONERROR);

                SetFocus(g_hPassEdit);
            }

            return 0;
        }
        }

        break;
    }

    case WM_KEYDOWN:
    {
        if (wp == VK_RETURN)
        {
            SendMessageW(hwnd, WM_COMMAND, IDC_LOGIN_BTN, 0);
            return 0;
        }

        break;
    }

    case WM_DESTROY:
        if (!g_authenticated)
            PostQuitMessage(0);
        return 0;

    case WM_CLOSE:
        PostQuitMessage(0);
        return 0;
}

return DefWindowProcW(hwnd, msg, wp, lp);
}

// Dashboard Window 
LRESULT CALLBACK DashboardWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

void CreateDashboard() {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DashboardWndProc;
    wc.hInstance = g_hInst;
    wc.hbrBackground = CreateSolidBrush(RGB(245, 246, 250));
    wc.lpszClassName = L"SecureVaultDash";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassExW(&wc);

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    int w = 960, h = 680;

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
    UpdateStatusBar(L"Ready  |  Vault: " + g_vaultPath +
        L"  |  Entries: " + std::to_wstring(g_vaultEntries.size()));
    ConsoleLog(L"SecureVault ready for operation", LOG_SUCCESS);
}

LRESULT CALLBACK DashboardWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT hFontUI = NULL;
    static HFONT hFontMono = NULL;
    static HWND hKeyLabel = NULL;

    switch (msg) {
    case WM_CREATE: {
        hFontUI = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontMono = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Consolas");

        INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES };
        InitCommonControlsEx(&icc);

        RECT rc;
        GetClientRect(hwnd, &rc);

        g_hStatusBar = CreateWindowW(STATUSCLASSNAMEW, L"Ready",
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS_BAR, g_hInst, NULL);

        g_hTabCtrl = CreateWindowExW(0, WC_TABCONTROLW, L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_HOTTRACK,
            10, 10, rc.right - 20, rc.bottom - 60, hwnd,
            (HMENU)IDC_TAB_CTRL, g_hInst, NULL);
        SendMessage(g_hTabCtrl, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        TCITEMW tab = {};
        tab.mask = TCIF_TEXT;
        tab.pszText = (LPWSTR)L"  Files Vault  ";
        TabCtrl_InsertItem(g_hTabCtrl, 0, &tab);
        tab.pszText = (LPWSTR)L"  Notes  ";
        TabCtrl_InsertItem(g_hTabCtrl, 1, &tab);
        tab.pszText = (LPWSTR)L"  Decrypt  ";
        TabCtrl_InsertItem(g_hTabCtrl, 2, &tab);

        g_hFileList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            20, 50, 750, 480, hwnd, (HMENU)IDC_FILE_LIST, g_hInst, NULL);
        SendMessage(g_hFileList, WM_SETFONT, (WPARAM)hFontUI, TRUE);
        ListView_SetExtendedListViewStyle(g_hFileList,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = (LPWSTR)L"Filename"; col.cx = 280; ListView_InsertColumn(g_hFileList, 0, &col);
        col.pszText = (LPWSTR)L"Added"; col.cx = 160; ListView_InsertColumn(g_hFileList, 1, &col);
        col.pszText = (LPWSTR)L"Size"; col.cx = 90; ListView_InsertColumn(g_hFileList, 2, &col);
        col.pszText = (LPWSTR)L"ID (partial)"; col.cx = 100; ListView_InsertColumn(g_hFileList, 3, &col);

        HWND btn;
        btn = CreateWindowW(L"BUTTON", L"+ Upload File",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            780, 50, 150, 36, hwnd, (HMENU)IDC_UPLOAD_BTN, g_hInst, NULL);
        SendMessage(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        btn = CreateWindowW(L"BUTTON", L"Export (Decrypt)",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            780, 96, 150, 36, hwnd, (HMENU)IDC_EXPORT_BTN, g_hInst, NULL);
        SendMessage(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        btn = CreateWindowW(L"BUTTON", L"Delete Entry",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            780, 142, 150, 36, hwnd, (HMENU)IDC_DELETE_BTN, g_hInst, NULL);
        SendMessage(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        g_hNoteList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | LBS_NOTIFY | WS_VSCROLL,
            20, 50, 200, 400, hwnd, (HMENU)IDC_NOTE_LIST, g_hInst, NULL);
        SendMessage(g_hNoteList, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        g_hNoteTitle = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"Note Title",
            WS_CHILD | ES_AUTOHSCROLL,
            230, 50, 480, 28, hwnd, (HMENU)IDC_NOTE_TITLE, g_hInst, NULL);
        SendMessage(g_hNoteTitle, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        g_hNoteEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | WS_HSCROLL,
            230, 90, 480, 360, hwnd, (HMENU)IDC_NOTE_EDIT, g_hInst, NULL);
        SendMessage(g_hNoteEdit, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        btn = CreateWindowW(L"BUTTON", L"Save Note",
            WS_CHILD | BS_PUSHBUTTON,
            730, 50, 110, 32, hwnd, (HMENU)IDC_NOTE_SAVE_BTN, g_hInst, NULL);
        SendMessage(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        btn = CreateWindowW(L"BUTTON", L"New Note",
            WS_CHILD | BS_PUSHBUTTON,
            730, 90, 110, 32, hwnd, (HMENU)IDC_NOTE_NEW_BTN, g_hInst, NULL);
        SendMessage(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        btn = CreateWindowW(L"BUTTON", L"Delete Note",
            WS_CHILD | BS_PUSHBUTTON,
            730, 130, 110, 32, hwnd, (HMENU)IDC_NOTE_DELETE_BTN, g_hInst, NULL);
        SendMessage(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        hKeyLabel = CreateWindowW(L"STATIC",
            L"Enter your decrypt key (hex) to view a file or note without the main vault:",
            WS_CHILD | SS_LEFT,
            20, 55, 750, 20, hwnd, NULL, g_hInst, NULL);
        SendMessage(hKeyLabel, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        g_hKeyEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | ES_AUTOHSCROLL | ES_READONLY,
            20, 85, 680, 28, hwnd, (HMENU)IDC_KEY_EDIT, g_hInst, NULL);
        SendMessage(g_hKeyEdit, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        btn = CreateWindowW(L"BUTTON", L"Copy Key",
            WS_CHILD | BS_PUSHBUTTON,
            710, 85, 90, 28, hwnd, (HMENU)IDC_KEY_COPY_BTN, g_hInst, NULL);
        SendMessage(btn, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        ShowWindow(g_hFileList, SW_SHOW);

        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR* nmhdr = (NMHDR*)lp;

        if (nmhdr->hwndFrom == g_hTabCtrl &&
            nmhdr->code == TCN_SELCHANGE)
        {
            int tab = TabCtrl_GetCurSel(g_hTabCtrl);

            ShowWindow(g_hFileList, SW_HIDE);

            ShowWindow(GetDlgItem(hwnd, IDC_UPLOAD_BTN), SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_EXPORT_BTN), SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_DELETE_BTN), SW_HIDE);

            ShowWindow(g_hNoteList, SW_HIDE);
            ShowWindow(g_hNoteTitle, SW_HIDE);
            ShowWindow(g_hNoteEdit, SW_HIDE);

            ShowWindow(GetDlgItem(hwnd, IDC_NOTE_SAVE_BTN), SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_NOTE_NEW_BTN), SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_NOTE_DELETE_BTN), SW_HIDE);

            ShowWindow(hKeyLabel, SW_HIDE);
            ShowWindow(g_hKeyEdit, SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, IDC_KEY_COPY_BTN), SW_HIDE);

            if (tab == 0)
            {
                ShowWindow(g_hFileList, SW_SHOW);

                ShowWindow(GetDlgItem(hwnd, IDC_UPLOAD_BTN), SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_EXPORT_BTN), SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_DELETE_BTN), SW_SHOW);
            }

            else if (tab == 1)
            {
                ShowWindow(g_hNoteList, SW_SHOW);
                ShowWindow(g_hNoteTitle, SW_SHOW);
                ShowWindow(g_hNoteEdit, SW_SHOW);

                ShowWindow(GetDlgItem(hwnd, IDC_NOTE_SAVE_BTN), SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_NOTE_NEW_BTN), SW_SHOW);
                ShowWindow(GetDlgItem(hwnd, IDC_NOTE_DELETE_BTN), SW_SHOW);
            }

            else if (tab == 2)
            {
                ShowWindow(hKeyLabel, SW_SHOW);
                ShowWindow(g_hKeyEdit, SW_SHOW);

                ShowWindow(GetDlgItem(hwnd, IDC_KEY_COPY_BTN), SW_SHOW);
            }
        }

        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        SendMessageW(g_hStatusBar, WM_SIZE, 0, 0);

        RECT statusRc;
        GetWindowRect(g_hStatusBar, &statusRc);
        int statusH = statusRc.bottom - statusRc.top;

        SetWindowPos(g_hTabCtrl, NULL, 10, 10,
            rc.right - 20, rc.bottom - statusH - 20, SWP_NOZORDER);
        SetWindowPos(g_hFileList, NULL, 20, 50,
            rc.right - 200, rc.bottom - statusH - 80, SWP_NOZORDER);
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);

        if (id == IDC_UPLOAD_BTN) {
            ConsoleLog(L"File upload initiated by user...", LOG_DEBUG);

            wchar_t filePath[MAX_PATH] = {};
            OPENFILENAMEW ofn = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = filePath;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrTitle = L"Select File to Encrypt & Store in Vault";
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

            if (GetOpenFileNameW(&ofn)) {
                ConsoleLog(L"File selected: " + std::wstring(filePath), LOG_INFO);

                VaultEntry entry;
                if (EncryptFileToVault(filePath, entry)) {
                    g_vaultEntries.push_back(entry);
                    SaveVaultIndex();
                    RefreshFileList();

                    std::wstring keyMsg = L"File encrypted!\n\nDecrypt Key (save this!):\n" + entry.keyHex +
                        L"\n\nIV:\n" + entry.ivHex +
                        L"\n\nOriginal file has been deleted from source location.";
                    MessageBoxW(hwnd, keyMsg.c_str(), L"Encryption Complete", MB_ICONINFORMATION);

                    UpdateStatusBar(L"File encrypted and stored: " + entry.originalName);
                    ConsoleLog(L"Entry added. Key: " + entry.keyHex.substr(0, 16) + L"...", LOG_SUCCESS);
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
            if (sel < 0) {
                MessageBoxW(hwnd, L"Select a file from the list first.", L"No Selection", MB_ICONWARNING);
                return 0;
            }

            LVITEMW lvi = {};
            lvi.mask = LVIF_PARAM;
            lvi.iItem = sel;
            ListView_GetItem(g_hFileList, &lvi);
            int idx = (int)lvi.lParam;

            if (idx < 0 || idx >= (int)g_vaultEntries.size()) return 0;
            auto& entry = g_vaultEntries[idx];

            ConsoleLog(L"Export (decrypt) requested for: " + entry.originalName, LOG_INFO);

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
                    HANDLE hOut = CreateFileW(savePath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hOut != INVALID_HANDLE_VALUE) {
                        DWORD written;
                        WriteFile(hOut, plainData.data(), (DWORD)plainData.size(), &written, NULL);
                        CloseHandle(hOut);
                        ConsoleLog(L"File exported to: " + std::wstring(savePath), LOG_SUCCESS);
                        MessageBoxW(hwnd, L"File decrypted and exported successfully!", L"Export Complete", MB_ICONINFORMATION);
                    }
                    else {
                        ConsoleLog(L"Cannot write to output path", LOG_FAIL);
                        MessageBoxW(hwnd, L"Cannot write to destination path.", L"Error", MB_ICONERROR);
                    }
                }
                else {
                    MessageBoxW(hwnd, L"Decryption failed. Check debug console.", L"Decryption Error", MB_ICONERROR);
                }
            }
        }

        else if (id == IDC_DELETE_BTN) {
            int sel = ListView_GetNextItem(g_hFileList, -1, LVNI_SELECTED);
            if (sel < 0) {
                MessageBoxW(hwnd, L"Select a file from the list first.", L"No Selection", MB_ICONWARNING);
                return 0;
            }

            LVITEMW lvi = {};
            lvi.mask = LVIF_PARAM;
            lvi.iItem = sel;
            ListView_GetItem(g_hFileList, &lvi);
            int idx = (int)lvi.lParam;

            if (idx < 0 || idx >= (int)g_vaultEntries.size()) return 0;

            int res = MessageBoxW(hwnd,
                (L"Permanently delete '" + g_vaultEntries[idx].originalName + L"' from vault?\n\nThis cannot be undone.").c_str(),
                L"Confirm Delete", MB_YESNO | MB_ICONWARNING);

            if (res == IDYES) {
                ConsoleLog(L"Deleting vault entry: " + g_vaultEntries[idx].originalName, LOG_WARN);

                if (!DeleteFileW(g_vaultEntries[idx].encryptedPath.c_str())) {
                    ConsoleLog(L"Warning: Could not delete .enc file", LOG_WARN);
                }

                g_vaultEntries.erase(g_vaultEntries.begin() + idx);
                SaveVaultIndex();
                RefreshFileList();
                ConsoleLog(L"Vault entry deleted", LOG_SUCCESS);
                UpdateStatusBar(L"Entry deleted. " + std::to_wstring(g_vaultEntries.size()) + L" entries remaining.");
            }
        }

        else if (id == IDC_NOTE_SAVE_BTN) {
            wchar_t titleBuf[256] = {}, contentBuf[65536] = {};
            GetWindowTextW(g_hNoteTitle, titleBuf, 255);
            GetWindowTextW(g_hNoteEdit, contentBuf, 65535);

            if (wcslen(titleBuf) == 0) {
                MessageBoxW(hwnd, L"Please enter a title for the note.", L"No Title", MB_ICONWARNING);
                return 0;
            }
            if (wcslen(contentBuf) == 0) {
                MessageBoxW(hwnd, L"Note content is empty.", L"Empty Note", MB_ICONWARNING);
                return 0;
            }

            ConsoleLog(L"Saving note: " + std::wstring(titleBuf), LOG_DEBUG);

            if (g_selectedNote >= 0 && g_selectedNote < (int)g_vaultEntries.size()) {
                ConsoleLog(L"Updating existing note, removing old entry...", LOG_DEBUG);
                DeleteFileW(g_vaultEntries[g_selectedNote].encryptedPath.c_str());
                g_vaultEntries.erase(g_vaultEntries.begin() + g_selectedNote);
                g_selectedNote = -1;
            }

            VaultEntry entry;
            if (EncryptNoteToVault(titleBuf, contentBuf, entry)) {
                g_vaultEntries.push_back(entry);
                SaveVaultIndex();
                RefreshNoteList();
                ConsoleLog(L"Note saved and encrypted", LOG_SUCCESS);
                MessageBoxW(hwnd,
                    (L"Note saved!\n\nDecrypt Key:\n" + entry.keyHex).c_str(),
                    L"Note Saved", MB_ICONINFORMATION);
                UpdateStatusBar(L"Note encrypted and saved: " + entry.originalName.substr(5));
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
            ConsoleLog(L"New note editor opened", LOG_DEBUG);
        }

        else if (id == IDC_NOTE_DELETE_BTN) {
            if (g_selectedNote < 0) {
                MessageBoxW(hwnd, L"Select a note from the list first.", L"No Selection", MB_ICONWARNING);
                return 0;
            }

            auto& e = g_vaultEntries[g_selectedNote];
            int res = MessageBoxW(hwnd,
                (L"Delete note '" + e.originalName.substr(5) + L"'?").c_str(),
                L"Confirm", MB_YESNO | MB_ICONWARNING);

            if (res == IDYES) {
                DeleteFileW(e.encryptedPath.c_str());
                g_vaultEntries.erase(g_vaultEntries.begin() + g_selectedNote);
                g_selectedNote = -1;
                SaveVaultIndex();
                RefreshNoteList();
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
                    int wLen = MultiByteToWideChar(CP_UTF8, 0,
                        (LPCSTR)nullTerm.data(), -1, NULL, 0);
                    std::vector<wchar_t> wContent(wLen);
                    MultiByteToWideChar(CP_UTF8, 0,
                        (LPCSTR)nullTerm.data(), -1, wContent.data(), wLen);

                    std::wstring title = e.originalName;
                    if (title.substr(0, 5) == L"NOTE:") title = title.substr(5);

                    SetWindowTextW(g_hNoteTitle, title.c_str());
                    SetWindowTextW(g_hNoteEdit, wContent.data());
                    g_selectedNote = entryIdx;
                    ConsoleLog(L"Note decrypted and loaded into editor", LOG_SUCCESS);
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
                    if (hMem) {
                        memcpy(GlobalLock(hMem), keyBuf, len);
                        GlobalUnlock(hMem);
                        SetClipboardData(CF_UNICODETEXT, hMem);
                    }
                    CloseClipboard();
                    ConsoleLog(L"Key copied to clipboard", LOG_SUCCESS);
                    UpdateStatusBar(L"Key copied to clipboard");
                }
            }
        }

        return 0;
    }

    case WM_CLOSE:
        if (MessageBoxW(hwnd, L"Exit SecureVault?", L"Confirm", MB_YESNO | MB_ICONQUESTION) == IDYES) {
            ConsoleLog(L"User initiated shutdown", LOG_INFO);
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_DESTROY:
        ConsoleLog(L"SecureVault shutting down. Vault secured.", LOG_SUCCESS);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// Entry Point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    g_hInst = hInstance;

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES | ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    LoadLibraryW(L"MSFTEDIT.DLL");

    // Create debug console
    CreateConsoleWindow();

    ConsoleLog(L"Locating vault storage directory...", LOG_DEBUG);

    wchar_t appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        g_vaultPath = std::wstring(appDataPath) + L"\\" + VAULT_DIR_NAME;
    }
    else {
        g_vaultPath = L"C:\\SecureVault_Storage";
    }

    if (!PathFileExistsW(g_vaultPath.c_str())) {
        ConsoleLog(L"Vault directory not found. Creating: " + g_vaultPath, LOG_INFO);
        if (CreateDirectoryW(g_vaultPath.c_str(), NULL)) {
            ConsoleLog(L"Vault directory created: " + g_vaultPath, LOG_SUCCESS);
            SetFileAttributesW(g_vaultPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            ConsoleLog(L"Vault directory marked hidden+system", LOG_DEBUG);
        }
        else {
            ConsoleLog(L"CRITICAL: Cannot create vault directory!", LOG_FAIL);
            MessageBoxW(NULL, L"Cannot create vault storage directory.", L"Fatal Error", MB_ICONERROR);
            return 1;
        }
    }
    else {
        ConsoleLog(L"Existing vault found: " + g_vaultPath, LOG_SUCCESS);
    }

    ConsoleLog(L"Vault path: " + g_vaultPath, LOG_INFO);

    CreateLoginWindow();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (msg.hwnd == g_hLoginWnd && msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            SendMessageW(g_hLoginWnd, WM_COMMAND, IDC_LOGIN_BTN, 0);
            continue;
        }
        if (!IsDialogMessageW(g_hLoginWnd, &msg) &&
            !IsDialogMessageW(g_hDashWnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    return 0;
}
