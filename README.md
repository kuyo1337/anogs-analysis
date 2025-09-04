# AnoSDK (anogs) Analysis: kgvn anti-cheat stuff

## Summary

[Huy Nguyen](https://github.com/34306) created this repository to perform reverse engineering analysis of **AnoSDK v6.8.31.11159** for learning and improvement purposes. The AnoGS binary itself contains **approximately 6,000–8,000 functions**, includes advanced obfuscation techniques, and has extensive data collection capabilities.

Me(kuyo) is here to learn more about mobile anti-cheats as well. Please note that we are reversing different versions of AnoSDK (Huy Nguyen is using v6.8.31.11159, and I am using v7.0.49.29225), so the results might be slightly different.

One more thing: if you block or delete the data it generates to hash the binary file, the game may not ban you immediately while playing, but it could ban you later after the server performs its analysis (they added checks for almost every game based on `game_id` and `user_info`).

Also, if you want to reverse-engineer ts with me, please message me on telegram: `kuyosense`.
---

## Binary Architecture Analysis

### General information
- **File Size**: Approximately 3.5MB (3,608,688 bytes)
- **Architecture**: arm64 iOS Framework  
- **Total Functions**: about 6,000-8,000
- **Analyzed Coverage**: about 150 core functions (2-3% of codebase)

### Function Distribution Analysis

```
Obfuscated/Unknown: ████████████████████████████████████████ 83% (~5,000 functions)
Utility Functions:  ████████ 8% (~500 functions)
Cryptographic Ops:  ███ 3% (~200 functions)
Memory Management:  ██ 1.5% (~100 functions)
File Operations:    ██ 1.3% (~80 functions)
Information Gather: ▌ 0.7% (~40 functions)
Anti-Analysis:      ▌ 0.4% (~25 functions)
String Obfuscation: ▌ 0.3% (~20 functions)
Reporting:          ▌ 0.3% (~15 functions)
Initialization:     ▌ 0.8% (~51 functions)
Core SDK:           ▌ 0.1% (~6 functions)
```

---

## Core System Analysis

### 1: SDK Entry Points
---

## Exported Entry Points

| Address    | Function                        | Purpose                               | Concern Level |
| ---------- | ------------------------------- | ------------------------------------- | ------------- |
| `0x116428` | `_AnoSDKInit`                   | Basic initialization                  | High          |
| `0x116454` | `_AnoSDKInitEx`                 | Extended initialization (license, ID) | High          |
| `0x116458` | `_AnoSDKSetUserInfo`            | Attach user information               | High          |
| `0x1164F4` | `_AnoSDKOnPause`                | Lifecycle hook (background)           | Medium        |
| `0x116514` | `_AnoSDKOnResume`               | Lifecycle hook (foreground)           | Medium        |
| `0x11656C` | `_AnoSDKOnRecvData`             | Data reception handler (server/IPC)   | High          |
| `0x1165C4` | `_AnoSDKIoctl`                  | Command/control interface             | High          |
| `0x1165C0` | `_AnoSDKIoctlOld`               | Legacy control interface              | Medium        |
| `0x1164A4` | `_AnoSDKSetUserInfoWithLicense` | User info setup w/ license validation | High          |
| `0x116534` | `_AnoSDKGetReportData`          | Report retrieval                      | High          |
| `0x1165CC` | `_AnoSDKGetReportData2`         | Report retrieval variant              | High          |
| `0x1165D0` | `_AnoSDKGetReportData3`         | Report retrieval variant              | High          |
| `0x1165D8` | `_AnoSDKGetReportData4`         | Report retrieval variant              | High          |
| `0x116550` | `_AnoSDKDelReportData`          | Report cleanup                        | Medium        |
| `0x1165D4` | `_AnoSDKDelReportData3`         | Report cleanup variant                | Medium        |
| `0x1165DC` | `_AnoSDKDelReportData4`         | Report cleanup variant                | Medium        |
| `0x1165C8` | `_AnoSDKFree`                   | Memory/resource cleanup               | Medium        |
| `0x1165E4` | `_AnoSDKRegistInfoListener`     | Register info callback listener       | Medium        |
| `0x1165E0` | `_AnoSDKOnRecvSignature`        | Signature validation handler          | High          |

---

## Core Function Mapping

Most of the above are wrappers,the **actual work** is done in:

* **`sub_48BA4`**

  * Core dispatcher for Init, InitEx, and SetUserInfo.
  * Handles global state setup and user data binding.

* **`AnoSDKInitEx_0`**

  * Extended initialization with string parameters.
  * Performs string concatenation and validation.
  * Calls into:

    * `sub_117174` (string lookup/decrypt)
    * `sub_2D304` (buffer formatting)
    * `sub_10A97C` (object allocator)
    * `sub_10C494` (data registrar)
    * `sub_3D1DC` (final commit/init).

---

## Example Decompiled Snippets

### `_AnoSDKInit`

```c
__int64 __fastcall AnoSDKInit(int a1) {
    sub_44BBC();                  // Pre-initialization (TLS, globals)
    return sub_48BA4(a1 >= 0, 0); // Delegate to core
}
```

### `_AnoSDKInitEx`

```c
__int64 AnoSDKInitEx() {
    return AnoSDKInitEx_0();
}
```

### `AnoSDKInitEx_0`

```c
// Extended init with optional string argument
v10 = (const char *)sub_117174(110);          // fetch string template
v11 = sub_2D304(v9, 255, "%s%s", v10, a2);   // concat template + arg
v12 = sub_10A97C(v11);                       // allocate/init structure
sub_10C494(v12, v9);                         // register structure
sub_3D1DC(v18);                              // commit initialization
```

---

## Behavior Summary

* **Initialization (`_AnoSDKInit`, `_AnoSDKInitEx`, `_AnoSDKSetUserInfo`)**
  -> All converge into `sub_48BA4`.
  -> Responsible for starting all monitoring systems and binding user/game identifiers.

* **Lifecycle (`_AnoSDKOnPause`, `_AnoSDKOnResume`)**
  -> Handle transitions between app states.
  -> Restart/stop background monitoring subsystems.

* **Control (`_AnoSDKIoctl`, `_AnoSDKIoctlOld`)**
  -> Provide external configuration.
  -> Dangerous since it may unlock hidden features or enforce checks remotely.

* **Data Handling (`_AnoSDKOnRecvData`, `_AnoSDKOnRecvSignature`)**
  -> Process incoming data from server or game host.
  -> Validates signatures & updates SDK state.

* **Reporting (`_AnoSDKGetReportData*`, `_AnoSDKDelReportData*`)**
  -> Collect and manage report structures before sending.
  -> Variants suggest multiple report formats (TDM/TSS).

* **Cleanup (`_AnoSDKFree`)**
  -> Free resources and internal allocations.

* **Callbacks (`_AnoSDKRegistInfoListener`)**
  -> Lets game register a callback for receiving SDK info.

---


### 2: Initialization System

AnoSDK employs a sophisticated distributed initialization system with **61 separate initialization functions** (`InitFunc_0` to `InitFunc_60`), making analysis significantly more challenging, if you want to have a deeper analysis, you could contribute to this project. Here are a few function i can checked:


| Address    | Function      | Purpose                                                         | Concern Level | Notes / Security Impact                                                                  |
| ---------- | ------------- | --------------------------------------------------------------- | ------------- | ---------------------------------------------------------------------------------------- |
| `0x2066C`  | `InitFunc_0`  | String Decryption Init (loads string decrypt handlers)          | **High**      | Critical: handles runtime decryption of SDK strings; tampering may expose secrets.       |
| `0x46A60`  | `InitFunc_1`  | Memory Cleanup Init (list cleanup + free on exit)               | Medium        | Medium: mainly housekeeping; misuse could cause leaks.                                   |
| `0x4F618`  | `InitFunc_2`  | Semaphore System Init (sem\_open / sem\_close / unlink mgmt)    | Medium        | Medium: synchronization; misconfig could lead to deadlocks.                              |
| `0x715F8`  | `InitFunc_3`  | Security Subsystem Init (secure structures + mutex cleanup)     | **High**      | Critical: sets up security-related structures; crucial for integrity.                    |
| `0xAA018`  | `InitFunc_4`  | Linked List Manager Init (alloc/free list nodes + mutex)        | **High**      | Critical: memory structure integrity; incorrect freeing could allow corruption.          |
| `0xAE540`  | `InitFunc_5`  | Memory Pool Init (custom allocator, mutex-protected)            | Medium        | Medium: efficiency / resource handling; potential leaks if bypassed.                     |
| `0xC575C`  | `InitFunc_6`  | Lock System Init (two independent recursive locks)              | Medium        | Medium: threading safety; protects shared resources.                                     |
| `0xC59A0`  | `InitFunc_7`  | Cache Lock Init (dedicated mutex for cache or shared state)     | Medium        | Medium: ensures cache consistency; low risk if bypassed.                                 |
| `0x228B24` | `InitFunc_8`  | Mutex A Init (recursive lock, cleanup on exit)                  | Low           | Low: general-purpose lock.                                                               |
| `0x228B80` | `InitFunc_9`  | Mutex B Init (recursive lock, cleanup on exit)                  | Low           | Low: general-purpose lock.                                                               |
| `0x228BDC` | `InitFunc_10` | Mutex C Init (recursive lock, cleanup on exit)                  | Low           | Low: general-purpose lock.                                                               |
| `0x228C38` | `InitFunc_11` | Mutex D Init (recursive lock, wrapped in ObjC autorelease pool) | Low           | Low: Objective-C integration, low risk.                                                  |
| `0x228CAC` | `InitFunc_12` | Internal Tree / Hierarchical Structure Init                     | Medium        | Medium: organizes internal data; structural corruption could propagate.                  |
| `0x228D08` | `InitFunc_13` | Internal Hierarchical Data / Tree Structure Init                | Medium–High   | Important: complex data structure initialization; tampering may break dependent systems. |

```cpp
// SDK Initialization Sequence with Security Notes
InitFunc_0  -> String decryption system setup        // HIGH: critical secrets
InitFunc_1  -> Memory management initialization      // MEDIUM: cleanup / free list
InitFunc_2  -> Threading / semaphore system activation // MEDIUM: sync primitives
InitFunc_3  -> Security subsystem deployment         // HIGH: security structures & mutexes
InitFunc_4  -> Linked list / monitoring system activation // HIGH: memory & data integrity
InitFunc_5  -> Memory pool / custom allocator setup // MEDIUM: efficiency + resource safety
InitFunc_6  -> Lock system initialization           // MEDIUM: recursive locks
InitFunc_7  -> Cache mutex initialization           // MEDIUM: shared state safety
InitFunc_8  -> Mutex A initialization               // LOW: general-purpose
InitFunc_9  -> Mutex B initialization               // LOW: general-purpose
InitFunc_10 -> Mutex C initialization               // LOW: general-purpose
InitFunc_11 -> Mutex D initialization (autorelease pool wrapped) // LOW: ObjC thread safety
InitFunc_12 -> Internal hierarchical structure setup // MEDIUM: internal data organization
InitFunc_13 -> Internal tree / hierarchical data finalization // MEDIUM-HIGH: complex data init
...47 more functions to discover,imma do it when im interested in ts again
```

---

## Obfuscation - NOT UP TO DATE AS OF 9/4/2025

### String Encryption

One of AnoSDK's most sophisticated components is its **multi-layer XOR-based string obfuscation system**, here's the address table and pseudo code:

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|------------|
| `0x114390` | `sub_114390` | Master XOR-based string deobfuscator | High |
| `0x5e9d0` | `sub_5E9D0` | Encrypted string table pointer | High |
| `0x5e9e4` | `sub_5E9E4` | Decrypted buffer management | High |
| `0x2ab40` | `sub_2AB40` | String duplication utilities | Low |
| `0x2ab1c` | `sub_2AB1C` | String concatenation | Low |
| `0x2aa4c` | `sub_2AA4C` | String length calculator | Low |

```cpp
// Simplified deobfuscation algorithm
char* deobfuscate_string(int index) {
    encrypted_table = &unk_2E1F68;     // Base encrypted data
    decrypted_buffer = &unk_349F09;    // Decrypted storage
    
    // Multi-layer XOR decryption with validation
    for (decrypt_attempts = 0; decrypt_attempts < 2; decrypt_attempts++) {
        xor_key = encrypted_table[index] ^ next_key_byte;
        
        for (i = 0; i < encrypted_length; i++) {
            decrypted_byte = encrypted_table[index + 2 + i] ^ 
                           ((xor_key + i) ^ 0x3B) + 4;
            decrypted_buffer[index + 2 + i] = decrypted_byte;
        }
        
        // Integrity verification
        if (calculate_checksum(decrypted_data) == ~stored_checksum) {
            return decrypted_buffer + index + 2;
        }
    }
    return decrypted_buffer + index + 2;
}
```

---

## Data Collection

### Dynamic Library Enumeration

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|---------------|
| `0x4f1c8` | `sub_4F1C8` | Library Enumeration Init - Initialize library scanning | High |
| `0x4f210` | `sub_4F210` | Library Iterator - Iterate through loaded libraries | High |
| `0x28e3c` | `sub_28E3C` | Image Count Getter - Get total dyld image count | Medium |
| `0x29484` | `sub_29484` | Image Name Getter - Get library name via dyld | Medium |
| `0x292f0` | `sub_292F0` | Image Header Getter - Get Mach-O header via dyld | Medium |
| `0x2938c` | `sub_2938C` | ASLR Slide Getter - Get memory slide for ASLR | Medium |

AnoSDK checked all loaded libraries in the target application:

```cpp
// Library enumeration process
library_count = _dyld_image_count(); 

for (i = 0; i < library_count; i++) {
    name = _dyld_get_image_name(i); 
    header = _dyld_get_image_header(i);
    slide = _dyld_get_image_vmaddr_slide(i);
    
    collect_library_info(name, header, slide);
}
```

### File System Scanning

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|---------------|
| `0x50e68` | `sub_50E68` | Master Detection Engine - Main file/process detection system | High |
| `0x5163c` | `sub_5163C` | File Access Tester - Test file access permissions | High |
| `0xb6d6c` | `sub_B6D6C` | Symbolic Link Reader - Read symlinks (readlink wrapper) | Medium |
| `0x54864` | `sub_54864` | Temp File Creator - Create temporary files for testing | Medium |
| `0x5f5e0` | `sub_5F5E0` | Permission Checker - Check file permissions | Medium |

### System sniff

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|---------------|
| `0xc2584` | `sub_C2584` | System Info Gatherer - Collect system information via sysctl | High |
| `0x117660` | `sub_117660` | Device Info Collector - Get device-specific information | High |
| `0xc2260` | `sub_C2260` | Configuration Detector - Detect system configuration | Medium |

Comprehensive device profiling through `sysctl()` calls:

```cpp
// Device data collected
hw.model         // "iPhone13,2"
hw.machine       // "iPhone13,2"  
hw.physmem       // Physical memory
```

---

## Anti-Analysis Protection

### Multi-Vector Anti-Debug System

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|---------------|
| `0x513ec` | `sub_513EC` | Anti-Debug Master - Main anti-debugging protection | High |
| `0x514b4` | `sub_514B4` | Signal-based Detection - Detect debugging via signals | High |
| `0x46b18` | `sub_46B18` | Timing-based Detection - Detect instrumentation via timing | High |
| `0x25714` | `sub_25714` | Dynamic API Resolver - Resolve API calls dynamically | High |

AnoSDK implements sophisticated debugging protection:

```cpp
// Fork-based debugger detection
pid_t child = fork();
if (child == 0) {
    exit(0);  // Child exits immediately
} else if (child > 0) {
    // Analyze fork behavior for debugger presence
    detect_debugger_via_fork_behavior();
}

// Self-protection via ptrace
ptrace(PT_DENY_ATTACH, 0, 0, 0);

// Signal-based detection
install_signal_handlers();
send_test_signals();
analyze_signal_delivery_timing();
```

### Dynamic API

The framework obscures its API usage through runtime calculate:

```cpp
// 40+ system APIs resolved dynamically
resolved_apis = {
    "dlopen", "dlsym", "dlclose",     // Dynamic loading
    "sysctl", "syscall", "ptrace",    // System control  
    "fopen", "fread", "fwrite",       // File operations
    "opendir", "readdir", "stat",     // Directory operations
    "getpid", "kill", "fork",         // Process control
    "connect", "send", "recv",        // Network operations
    "_dyld_get_image_name",           // Library enumeration
    // ... 30+ more, you can check it in Import tabs
};
```

---

## Data Transmission and Reporting System (IMPORTANT)

### Report Generation

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|---------------|
| `0x46c28` | `sub_46C28` | Report Builder - Build TDM/TSS reports | High |
| `0x47210` | `sub_47210` | Event Monitor - Monitor and report events | High |
| `0x47070` | `sub_47070` | Monitoring Controller - Control monitoring operations | Medium |
| `0x45e44` | `sub_45E44` | Version String Generator - Generate SDK version info | Low |

### Data Processing

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|---------------|
| `0x24050` | `sub_24050` | Data Processor - Process collected data for reporting | High |
| `0x2aa4c` | `sub_2AA4C` | Length Calculator - Calculate data lengths | Low |
| `0x2ac20` | `sub_2AC20` | Memory Copy - Copy data between buffers | Low |

### Should I block this report to the server?

- NO, don't do it, otherwise you could risk your account. Because if the server didn't checked the report sent from your device with the user_info and game_id, it will ban you when you log in back the game (aka a Remote fine).
- Then how can I avoid ban? Just patch the function they collect information from your device, I do MSHookFunction to `sub_46C28` and `sub_47210`. On `sub_46C28`, they create report data at every first time you enter the game and stop, while `sub_47210` sending your device report repeatly to data server every 10-15s.

### TDM/TSS Report Structure

AnoSDK generates structured reports transmitted to servers:

```cpp
// Report payload structure
typedef struct {
    char magic[4];          // "TDM" header
    uint32_t version;       // SDK version
    uint32_t report_type;   // Report classification
    uint64_t timestamp;     // Collection time
    uint32_t payload_size;  // Data length
    
    // Dynamic payload with encrypted events
    struct {
        uint32_t event_id;    // 110100, 110101, 110102, etc.
        uint32_t data_type;   // Content type identifier
        uint32_t data_length; // Content length
        uint8_t data[];       // Encrypted content
    } events[];
    
    uint32_t checksum;      // Integrity verification
} TDMReport;
```
---

## Support Functions

### Memory

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|---------------|
| `0x6474` | `sub_6474` | Memory Allocator - Custom memory allocation | Medium |
| `0x5cb4` | `sub_5CB4` | Buffer Manager - Manage data buffers | Medium |
| `0x63d0` | `sub_63D0` | Memory Cleanup - Clean up allocated memory | Medium |

### String

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|---------------|
| `0xefd90` | `sub_EFD90` | String Suffix Checker - Check if string ends with pattern | Low |
| `0x2a9a4` | `sub_2A9A4` | String Comparator - Compare strings | Low |
| `0x2a9cc` | `sub_2A9CC` | String Copy - Copy strings safely | Low |

### File Operations

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|---------------|
| `0x71778` | `sub_71778` | File Opener - Open files (fopen wrapper) | Medium |
| `0x71abc` | `sub_71ABC` | File Closer - Close files (fclose wrapper) | Medium |
| `0x72900` | `sub_72900` | Directory Scanner - Scan directories | Medium |
| `0x729d0` | `sub_729D0` | Directory Reader - Read directory entries | Medium |
| `0x72aa0` | `sub_72AA0` | Directory Cleanup - Clean up directory resources | Medium |

---

### Base on the open source docs of anogs (outdated)

```cpp
// the function AnoSDKInitEx control the push thing
AnoSDKInitEx(game_id, app_key);
//or 
AnoSDKInit_0(game_id, app_key);
//and
AnoSDKIoctl(AnoSdkCmd_CommQuery, "CloseUserTagScan");

```
I'd recommend you should checking more details on `AnoSDKIoctl` and `AnoSDKInitEx` (or `AnoSDKInit_0` for this binary case).

---

## Conclusion

AnoSDK represents a sophisticated example of modern mobile security engineering, demonstrating advanced anti-cheat capabilities alongside significant privacy implications. While technically impressive and serving legitimate security purposes, the framework's extensive data collection capabilities warrant careful consideration and responsible implementation.

## Other stuff

- **Trust issue?**: idk, you can use this as a base document if you want to do more analysis than i did.
- **Tools Used**: IDA Pro, MCP and Claude (AI thing for deobfuscate function more clearly).
