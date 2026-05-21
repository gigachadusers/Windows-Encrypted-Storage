# SecureVault

**Local AES-256 Encrypted File & Note Storage for Windows**

No internet. No cloud. No third-party libraries. Everything stays on your machine.

---

## About This Project

SecureVault is a fully local, real encryption vault built entirely on Windows native APIs. All cryptographic operations use **Windows CNG (Cryptography Next Generation)** — no OpenSSL, no external dependencies.

### Development Credits

- **Core application logic, encryption engine, vault system, file handling, and all security architecture** — coded by wizz3ard / bosslivin on tg
- **GUI frontend design and debug console UI** — designed with the assistance of AI (Claude by Anthropic), including the dark theme, custom-drawn controls, login screen layout, key popup dialog, and coloured debug console output

---

## Features

- Password-protected login screen
- **AES-256-CBC encryption** via Windows CNG BCrypt API
  - 256-bit keys generated with `BCryptGenRandom` (CSPRNG)
  - Fresh 128-bit IV generated per file — never reused
  - PKCS7 block padding
- **File vault** — upload any file, it's encrypted and the original is zero-wiped and deleted
- **Per-file unique decrypt key** — displayed as a 64-char hex string after encryption
- **Key popup dialog** with one-click Copy Key and Copy IV buttons
- **Note editor** — write, save, and encrypt notes directly in-app
- **Export / Decrypt** — restore any stored file back to disk
- **Colour-coded debug console** — real-time operation log with green (success), red (fail), amber (warn), and blue (debug) entries and timestamps
- **All local** — vault lives in `%APPDATA%\SecureVault_Storage` (hidden + system folder)

---

## How to Build

### Option A — Visual Studio / MSVC (recommended)

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) with "Desktop development with C++"
2. Open **Developer Command Prompt for VS**
3. Navigate to the folder containing `main.cpp`
4. Run:

```
cl.exe /W3 /O2 /EHsc /MD /DUNICODE /D_UNICODE main.cpp ^
  /link bcrypt.lib shlwapi.lib comdlg32.lib comctl32.lib ^
  user32.lib gdi32.lib kernel32.lib shell32.lib uxtheme.lib dwmapi.lib ^
  /SUBSYSTEM:WINDOWS /OUT:SecureVault.exe
```

### Option B — MinGW-w64 (GCC)

1. Install MinGW-w64 from [winlibs.com](https://winlibs.com/) or via MSYS2
2. Ensure `g++` is in your PATH
3. Run:

```
g++ -std=c++17 -O2 -DUNICODE -D_UNICODE -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 ^
  main.cpp -o SecureVault.exe ^
  -lbcrypt -lshlwapi -lcomdlg32 -lcomctl32 -luxtheme -ldwmapi -mwindows
```

---

## Running

Double-click `SecureVault.exe`. Two windows open simultaneously:

1. **Debug Console** — black terminal-style window with colour-coded real-time logs
2. **Login Window** — enter the vault password to unlock

**Default password:** `1234`

To change it, edit line 37 in `main.cpp`:
```cpp
const wchar_t* VAULT_PASSWORD = L"1234";
```

---

## Usage

### Files Tab
- Click **+ Upload File** to pick any file
- It is read into memory, AES-256-CBC encrypted with a freshly generated key and IV, written to the vault as a `.enc` blob, and the original is **zero-overwritten then deleted**
- A popup shows your **Decrypt Key** (64-char hex) and **IV** (32-char hex) — each has a **Copy** button. Save both somewhere safe — they cannot be recovered
- **Export & Decrypt** — select a file from the list and save the decrypted copy anywhere
- **Delete Entry** — permanently removes the vault entry and its `.enc` file

### Notes Tab
- Left panel shows all saved notes
- Click a note to automatically decrypt and load it into the editor
- Edit freely, then **Save Note** re-encrypts it with a fresh key
- **New Note** clears the editor
- **Delete Note** permanently removes it

### Decrypt Key Tab
- Shows the encryption key for manual use
- **Copy** button copies to clipboard

### Debug Console
- Click **Debug Console** on the Files tab to toggle the console window
- Colour coding:
  - 🟢 `[+]` Green — success
  - 🔴 `[!]` Red — failure / error
  - 🟡 `[~]` Amber — warning
  - 🔵 `[>]` Blue — debug / info
  - ⬜ `[-]` Grey — general info

---

## Security Details

| Property | Value |
|---|---|
| Algorithm | AES-256-CBC |
| Key length | 256 bits (32 bytes) |
| IV length | 128 bits (16 bytes) |
| Padding | PKCS7 |
| Key generation | `BCryptGenRandom` — OS-level CSPRNG |
| Crypto API | Windows CNG (`bcrypt.dll`) — no OpenSSL |
| Storage location | `%APPDATA%\SecureVault_Storage\` |
| Vault directory | Marked `HIDDEN + SYSTEM` |
| Original file deletion | Zero-overwrite pass, then `DeleteFileW` |
| Key storage | Stored in `vault.idx` (plaintext, protected by OS login) |

### Encrypted File Format (`.enc`)

```
Offset   Size   Content
0        8      Magic: 53 56 41 55 4C 54 01 00  ("SVAULT\x01\x00")
8        16     IV (128-bit, random, fresh per file)
24       N      AES-256-CBC ciphertext (PKCS7 padded)
```

### Encrypted Note Format (`.enc`)

```
Offset   Size   Content
0        8      Magic: 53 56 4E 4F 54 45 01 00  ("SVNOTE\x01\x00")
8        16     IV (128-bit, random, fresh per note)
24       N      AES-256-CBC ciphertext of UTF-8 note text
```

### Why AES-256-CBC?

AES-256 is the industry standard for symmetric encryption. CBC (Cipher Block Chaining) mode ensures that identical plaintext blocks produce different ciphertext due to IV chaining. Each file gets its own cryptographically random 256-bit key and 128-bit IV via `BCryptGenRandom`, making brute force attacks against individual files computationally infeasible with current hardware.

---

## Vault Location

```
C:\Users\<You>\AppData\Roaming\SecureVault_Storage\
    vault.idx           ← index of all entries (filenames, keys, IVs, timestamps)
    <hex-id>.enc        ← encrypted file blob
    <hex-id>.enc        ← encrypted note blob
    ...
```

The folder is flagged `HIDDEN + SYSTEM` and won't appear in standard Explorer views. To find it: `Win+R` → `%APPDATA%\SecureVault_Storage`.

---

## Limitations & Honest Notes

- `vault.idx` stores filenames and keys in **plaintext**. It is protected by your Windows login and the hidden folder flag — but it is not itself encrypted. For additional protection, enable Windows EFS on the vault directory (right-click → Properties → Advanced → Encrypt contents).
- The secure delete is a **single zero-overwrite pass**. On SSDs, wear-levelling means remnants may persist at the firmware level. For truly sensitive files, use a dedicated secure-erase tool before uploading.
- The hardcoded password (`1234` by default) should be changed before using this for anything sensitive. A future version may support hashed password storage.
- Losing `vault.idx` means losing your keys. Back up the entire vault folder, not just the `.enc` files.

---

## Dependencies

Windows built-in only — no third-party libraries required:

| Library | Purpose |
|---|---|
| `bcrypt.dll` | AES-256-CBC encryption, random key generation (CNG) |
| `shlwapi.dll` | Path utilities |
| `comdlg32.dll` | File open / save dialogs |
| `comctl32.dll` | ListView, TabControl, StatusBar |
| `msftedit.dll` | RichEdit control (coloured debug console) |
| `uxtheme.dll` | Visual style support |
| `dwmapi.dll` | Desktop Window Manager integration |

---

## License

Do whatever you want with it. Not responsible for lost files — save your keys.
