# dacltool — Inspect and manage Windows file/folder DACL permissions from an interactive console

dacltool is a small Windows security utility that works on NTFS Discretionary Access
Control Lists. A DACL is the part of an object's security descriptor that lists who can
access the object and what they can do with it: it is a sequence of Access Control
Entries (ACEs), where each ACE binds a SID (a user, group, or computer account) to a
32-bit access mask (a set of rights such as `FILE_READ_DATA`, `DELETE`, `GENERIC_ALL`),
and marks it as either a grant or a deny entry. Access decisions are made by the
security reference monitor, which evaluates the ACEs against the access token produced
for the user's logon session — a process or thread acts on an object according to the
rights that token matches in the DACL.

Under the hood dacltool uses the Win32 Security/CACE API directly: it reads security
descriptors with `GetNamedSecurityInfoW(SE_FILE_OBJECT, ...)`, walks the ACEs with
`GetAce`, converts SIDs to readable strings with `ConvertSidToStringSid` and resolves
their account names with `LookupAccountSid`, and, for the enumeration mode, performs a
token-group membership check with `CheckTokenMembership` so that only ACEs matching the
token of the current user are shown. Shortcut (`.lnk`) files submitted as targets are
resolved to their real target path first via the `IShellLink` / `IPersistFile` COM
interfaces. New permissions are added with `SetEntriesInAcl` + `SetNamedSecurityInfo`
(using `TRUSTEE_IS_NAME` and inheritable ACE flags so child objects receive the new
entry), and permission removal rebuilds a new ACL that keeps every ACE except those
whose SID equals the target user's SID, then restores it with `PROTECTED_DACL_SECURITY_INFORMATION`.

Permission masks (rights) are entered and printed using the same one-letter and
short-letter flags that `icacls` uses, so the tool is easy to use next to built-in
tooling.

dacltool provides 3 modes:

- **enum** — enumerate the DACL of a file or folder (optionally recursively) and print
  every ACE that matches the current token, as an aligned ASCII table showing the SID,
  account name, ACE type, and access mask.
- **add** — grant a user/group new permissions on a file or folder by appending a new
  inheritable ALLOW ACE to the DACL.
- **remove** — remove every ALLOW/DENY ACE belonging to a given user from the DACL of a
  file or folder (optionally over the whole tree).

All interaction is done through `std::cin` / `std::cout`. There are no command
line arguments, no flags, and no configuration files.

---

## Features

- **DACL enumeration with token filtering** — shows exactly the ACEs that apply to the
  current user (`CheckTokenMembership` against the current thread's effective token),
  not the raw dump of the whole descriptor.
- **Readable access-mask decoding** — each ACE mask is printed as its named rights list
  (`FILE_EXECUTE`, `WRITE_DAC`, `GENERIC_ALL`, ...).
- **Recursive folder scan** — with the `-r` option, every child file and folder is
  visited and its DACL is shown in sequence.
- **Shortcut resolution** — a `.lnk` target is resolved via `IShellLink::Resolve` so the
  DACL of the real target is inspected, not the shortcut file's.
- **icacls-style permission flags** — grant permissions with `user:(RX,W)` syntax;
  masks map to the same constants `icacls` uses.
- **Inheritable ACL edits** — added ACEs use `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`
  so new child folders/files inherit the grant.
- **ACE-preserving removal** — the remove mode only drops ACEs of the target user, and
  re-applies the rest of the ACL untouched, with `PROTECTED_DACL_SECURITY_INFORMATION`.

## Requirements

- Windows 10/11 (NTFS filesystem; the tool only manages `SE_FILE_OBJECT` descriptors).
- A C++17 toolchain:
  - MSVC 2019 or later (Build Tools with "Desktop development with C++"), or
  - MinGW-w64 (`g++`, e.g. from MSYS2).
- CMake 3.15+ (for Options A and B below).
- Runtime DLLs are system libraries only (`advapi32`, `shell32`, `ole32`),
  so no extra dependencies need to be installed.

## Build instructions

### Option A — CMake (MSVC)

Open a *Developer Command Prompt for VS* (or use any shell with CMake:

```console
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

The executable lands in `build\Release\dacltool.exe`.

### Option B — CMake (MinGW-w64 + Ninja)

```console
cmake -G Ninja -B build
cmake --build build
```

### Option C — MinGW-w64 (g++) directly

```console
g++ -std=c++17 -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0A00 -DWIN32_LEAN_AND_MEAN -O2 -o dacltool.exe ^
    main.cpp utils.cpp table.cpp dacl-enum.cpp add-per.cpp remove-per.cpp lnk-check.cpp ^
    -ladvapi32 -lshell32 -lole32 -luuid
```

(Under a plain `cmd.exe` shell, use `-o dacltool.exe ...` on one line; the `^` is only a
line continuation.)

## Usage

Run `dacltool.exe` from a console. A menu is shown inside the terminal itself — this is
`std::cin` / `std::cout` interaction (wide strings; the console runs in `_O_U16TEXT`
mode), not command-line usage:

```text
==============================================
        dacltool - Windows DACL Tool
==============================================
Select mode:
  1) enum    - list the DACL ACEs of a file or folder that match the current token
  2) add     - grant a user new permissions on a file or folder
  3) remove  - remove all ACEs of a user from a file or folder DACL
  0) exit
> 1
```

### Mode 1 — enum: list DACL entries matching the current token

After choosing `1`, type the arguments on the same prompt line as the tool tells you:

```text
Arguments (e.g. -r C:\folder | C:\file.txt | target.lnk): -r C:\Users\admin\Desktop\choco
```

Result (illustrative):

```text
--- DACL for: C:\Users\admin\Desktop\choco ---
+---------+-----------+-------------------------+------------------------------------------+
| SID     | Name      | aceType                 | AccessMask                               |
+---------+-----------+-------------------------+------------------------------------------+
| S-1-5-21-...-1002 | DESKTOP-IT9PVVP\choco | ACCESS_ALLOWED_ACE_TYPE | FILE_READ_DATA, FILE_EXECUTE, ...
+---------+-----------+-------------------------+------------------------------------------+
```

**Field notes**

- First argument is a path to a file or a folder. If the path contains spaces, quote the
  whole argument (the tool re-parses your line with `CommandLineToArgvW`).
- The parser detects automatically whether the path is a directory (`dir` arg) or a
  plain file (`file` arg); exactly one path is expected.
- `-r` (optional) — enable recursive enumeration over the directory tree. It is only
  valid together with a folder; using it with a file path is rejected.
- Passing a `.lnk` shortcut resolves the real target folder/file first.
- Non-standard ACE types and invalid SIDs are printed as skipped messages rather than
  crashing the scan.
- Only ACEs matching the current token (user's groups + the user itself) appear in the
  table — this makes it easy to answer "what can I actually do with this folder?".

### Mode 2 — add: grant permissions to a user

```text
Arguments (e.g. C:\folder -g user1:(RX,W)): "C:\My Temp Folder" -g Domain\alice:(F,M)
```

**Field notes**

- `<file_path>` — target file or folder; quote it when it contains spaces.
- `-g <trustee:(perm1,perm2,...)>` — the grant entry. The trustee is an account name
  (`user1` or `DOMAIN\user`), and the parentheses contain one or more icacls-style
  permission flags separated by commas. The whole `-g` argument must be given **after**
  the path.
- The mapping of permission flags is the same as `icacls`:

  | Flag   | Meaning                                   |
  |--------|-------------------------------------------|
  | `F`    | Full control                               |
  | `M`    | Modify                                     |
  | `RX`   | Read and execute                           |
  | `R`    | Read-only                                  |
  | `W`    | Write-only                                 |
  | `D`    | Delete                                     |
  | `RC`   | Read control                               |
  | `WDAC` | Write DACL                                 |
  | `WO`   | Write owner                                |
  | `S`    | Synchronize                                |
  | `AS`   | Access system security                     |
  | `MA`   | Maximum allowed                            |
  | `GR`   | Generic read                               |
  | `GW`   | Generic write                              |
  | `GE`   | Generic execute                            |
  | `GA`   | Generic all                                |
  | `RD`   | Read data / list directory                 |
  | `WD`   | Write data / create file                   |
  | `AD`   | Append data / create subdirectory          |
  | `REA`  | Read extended attributes                   |
  | `WEA`  | Write extended attributes                  |
  | `X`    | Execute / traverse                         |
  | `DC`   | Delete child                               |
  | `RA`   | Read attributes                            |
  | `WA`   | Write attributes                           |

- The new ACE is an ALLOW ACE, with inheritance flags
  `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`, so it propagates to child objects.
- The rest of the existing DACL is preserved: `SetEntriesInAcl` merges the new ACE into
  the old ACL, and the merged ACL is written back with `SetNamedSecurityInfo`.

### Mode 3 — remove: delete a user's ACEs from a DACL

```text
Arguments (e.g. -d user1 "C:\My Temp Folder" -r): -d Domain\bob "C:\Projects\secret"
```

**Field notes**

- `-d <user_name>` — the account whose ACEs should be removed. The account is resolved
  to a SID once via `LookupAccountName` + `ConvertSidToStringSid`.
- `<file_path>` — target file or folder. If the target is a folder **and** `-r` is
  present, the whole tree is walked first with a recursive directory scan, then every
  child descriptor is processed in turn.
- `-r` (optional) — recursive mode; only makes sense for directories.
- During processing, all `ACCESS_ALLOWED_ACE`-type and `ACCESS_DENIED_ACE`-type ACEs are
  copied to a freshly built ACL except the ones whose SID matches the removed user.
  Non-standard ACE types are copied unchanged.
- The rebuilt ACL is written back with the `PROTECTED_DACL_SECURITY_INFORMATION` flag,
  meaning the inheritance from the parent folder is cut (the DACL becomes protected) —
  that is why previously inherited ACEs from the parent do not return after removal.
- The final message confirms the removal was applied for every processed file.

---

## Permissions and notes

- Running the tool does not require Administrator rights just to *start* it; DACL
  enumeration of your own files works from a regular user token. Enumerating ACLs of
  other users' files (e.g. `C:\Windows\System32`) may produce access errors where the
  caller lacks `READ_CONTROL` on some object — those paths are reported, not skipped
  silently.
- **add / remove** modes *modify* security descriptors. Modifying a DACL requires either
  ownership of the object or the WRITE_DAC capability on it; for system-owned files,
  run the console elevated.
- Writing back the ACL with the remove mode sets `PROTECTED_DACL_SECURITY_INFORMATION`,
  so it makes the DACL protected — inherited permissions from parent folders no longer
  apply after that operation, by design. Use standard tools (`icacls`, Explorer) to
  restore if needed.
- Passing SIDs that belong to built-in principals such as `S-1-5-6` (SERVICE) or
  `S-1-1-0` (Everyone) works the same way.
- The console is switched to `_O_U16TEXT` mode on startup (`_setmode` with
  `std::wcout` / `std::wcin`); mixing `stdio.h`-based narrow prints into the same
  console in this mode will trigger an assertion — stick to the wide I/O helpers in
  `utils.h`.
- Quoting rules mirror `CommandLineToArgvW`: a path containing spaces must be wrapped
  in double quotes, e.g. `"C:\your folder"`.
- **Responsible use only.** dacltool exists for legitimate administration, auditing and
  incident-response workflows on systems you own or are authorized to administer.
  Stripping a user's ACEs or granting broad rights on critical folders can lock you (or
  your applications) out — test on disposable folders first, and prefer to keep an
  escape hatch (`icacls /restore` etc. with a backed-up security descriptor).

## Project layout

- `main.cpp` — entry point: wide-console setup, interactive mode menu, dispatch of the
  three features.
- `dacl-enum.cpp` / `dacl-enum.h` — DACL enumeration: directory walker
  (`list_files`), SID / access-mask pretty print, and
  `analyze_dac_with_token` (the enum feature; token-matching table builder).
- `add-per.cpp` / `add-per.h` — grant ACE feature (`AddSidAce`) with the
  `icacls`-style permission parser `ParseICaclsEntry` and the `permissionMappings` flag table.
- `remove-per.cpp` / `remove-per.h` — ACE removal feature (`RemoveSidAce`) and
  username → SID resolution (`get_sid_string`).
- `lnk-check.cpp` / `lnk-check.h` — shortcut helpers: `is_lnk_file` and COM-based
  `resolve_lnk_path` (`IShellLink`).
- `table.cpp` / `table.h` — generic wide-string ASCII table renderer
  (`generate_table`, `wrap_text`, `split_into_words`) used for DACL output.
- `utils.cpp` / `utils.h` — console helper `print_line` shared by all features.
- `CMakeLists.txt` — CMake build description (MSVC and MinGW-w64).
