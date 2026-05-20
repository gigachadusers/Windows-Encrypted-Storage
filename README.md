# SecureVault — Local Encrypted File & Note Storage

A fully local, real AES-256-CBC encrypted file vault and notepad for Windows.
No internet connection. No cloud. No third-party libraries.

---

## Features

- **Password-protected login** (hardcoded — change `VAULT_PASSWORD` in source)
- **AES-256-CBC encryption** via Windows CNG (Cryptography Next Generation)
  - 256-bit keys generated via `BCryptGenRandom`
  - 128-bit IVs generated fresh for every file
  - PKCS7 block padding
- **File vault**: Upload any file → it gets encrypted, the original is wiped
- **Unique decrypt key** per file — shown as a 64-char hex string you must save
- **Note editor**: Write, save, encrypt notes directly in the app
- **Export (decrypt)**: Decrypt any stored file back to disk using the stored key
- **Green/red debug console**: Real-time operation log with timestamps
- **All local**: Vault stored in `%APPDATA%\SecureVault_Storage` (hidden folder)

---

## How to Build

### Option A — Visual Studio / MSVC (recommended)

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) with "Desktop development with C++"
2. Open **Developer Command Prompt for VS**
3. Navigate to the folder containing `SecureVault.cpp`
4. Run `build.bat` — or manually:

```
cl.exe /W3 /O2 /EHsc /MD /DUNICODE /D_UNICODE SecureVault.cpp ^
  /link bcrypt.lib shlwapi.lib comdlg32.lib comctl32.lib ^
  user32.lib gdi32.lib kernel32.lib shell32.lib ^
  /SUBSYSTEM:WINDOWS /OUT:SecureVault.exe
```

### Option B — MinGW-w64 (GCC)

1. Install MinGW-w64 from [winlibs.com](https://winlibs.com/) or via MSYS2
2. Ensure `g++` is in your PATH
3. Run `build.bat` — or manually:

```
g++ -std=c++17 -O2 -DUNICODE -D_UNICODE -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 ^
  SecureVault.cpp -o SecureVault.exe ^
  -lbcrypt -lshlwapi -lcomdlg32 -lcomctl32 -mwindows
```

---

## Running

Double-click `SecureVault.exe`.

Two windows will open:
1. **Debug Console** — black window showing real-time operation logs
2. **Login Window** — enter the vault password

**Default password:** `SecurePass123!`

To change it, edit line 17 in `SecureVault.cpp`:
```cpp
const wchar_t* VAULT_PASSWORD = L"SecurePass123!";
```

---

## Usage

### Files Tab
- **Upload File** — opens a file picker; the file is encrypted and the original is **deleted and wiped with zeros**
- A dialog shows your **decrypt key** (64-char hex) — **save this somewhere safe**
- **Export (Decrypt)** — select a file in the list and export it decrypted to any location
- **Delete Entry** — permanently removes the entry and its `.enc` file

### Notes Tab
- Left panel: list of saved notes
- Click any note to **decrypt and load** it into the editor
- Edit freely, then click **Save Note** to re-encrypt and save
- **New Note** clears the editor for a fresh note
- **Delete Note** permanently removes it

### Decrypt Tab
- Displays the encryption key for the currently selected file
- **Copy Key** copies it to clipboard

---

## Security Details

| Property | Value |
|----------|-------|
| Algorithm | AES-256 (CBC mode) |
| Key length | 256 bits (32 bytes) |
| IV length | 128 bits (16 bytes) |
| Padding | PKCS7 |
| Key generation | `BCryptGenRandom` (CSPRNG) |
| API | Windows CNG (`bcrypt.dll`) |
| Storage | `%APPDATA%\SecureVault_Storage\` |
| Index | Plain text (vault.idx) — protected by OS login |
| Original file deletion | Overwritten with zeros, then deleted |

### File Format (.enc files)

```
Offset  Size   Content
0       8      Magic bytes: 53 56 41 55 4C 54 01 00 ("SVAULT\x01\x00")
8       16     IV (128-bit, random)
24      N      AES-256-CBC ciphertext (PKCS7 padded)
```

### Notes Format (.enc files)

```
Offset  Size   Content
0       8      Magic bytes: 53 56 4E 4F 54 45 01 00 ("SVNOTE\x01\x00")
8       16     IV (128-bit, random)
24      N      AES-256-CBC ciphertext of UTF-8 note text
```

---

## Vault Location

```
C:\Users\<You>\AppData\Roaming\SecureVault_Storage\
    vault.idx          ← index of all entries
    <hex-id>.enc       ← encrypted file data
    <hex-id>.enc       ← encrypted note data
    ...
```

The directory is marked `HIDDEN + SYSTEM` so it won't appear in normal Windows Explorer views.

---

## Limitations & Notes

- The vault index (`vault.idx`) stores filenames and keys in plaintext. It is protected by Windows login credentials and the hidden+system flag, but is not itself encrypted. For extra security, you can encrypt the vault directory using Windows EFS (right-click → Properties → Advanced → Encrypt contents).
- The "secure delete" is a single zero-overwrite pass. For truly sensitive files on HDDs, use a dedicated secure-erase tool. On SSDs, the OS/SSD firmware handles secure erase differently.
- The hardcoded password should be changed before deploying for real use.
- Keys are stored in the vault index. If you lose the vault, your keys are gone too. Keep backups of keys for important files.

---

## Dependencies

Only Windows built-in libraries (no third-party):
- `bcrypt.dll` — AES-256-CBC encryption (Windows CNG)
- `shlwapi.dll` — Shell utility functions
- `comdlg32.dll` — File open/save dialogs
- `comctl32.dll` — ListView, TabControl
- `msftedit.dll` — RichEdit control (debug console colours)

All available on Windows 7+ with no additional installation.
