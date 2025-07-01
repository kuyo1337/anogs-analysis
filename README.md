# AnoSDK (anogs) Analysis: kgvn anti-cheat stuff

## Summary

I made this repo just want to do reverse engineering analysis of **AnoSDK v6.8.31.11159** for learn and improvement purpose. The anogs binary itself contains **approximately 6,000-8,000 functions**, included advanced obfuscation techniques, and extensive data collection capabilities.

I also checked the open source documentation of them, you can read it [here, in Chinese](https://github.com/silentninjabee/ACE-Anticheat-SDK-Documentation/blob/master/10.0.0_%E6%89%8B%E6%B8%B8%E5%8F%8D%E5%A4%96%E6%8C%82SDK/10.2.9_IOS%20C%E7%89%88%E6%8E%A5%E5%85%A5%E6%95%99%E7%A8%8B.md) (well I also don't know Chinese so just use Google Translate)

One more thing is if you blocked or delete the data it created to hash the binary file, the game will not ban you at the right time you play, but it will ban you after the server doing analysis (they added check for almost game base on game_id and user_info).

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

The foundation of AnoSDK contains these functions:

| Address | Function | Purpose | Concern Level  |
|---------|----------|---------|--------------|
| `0x10fe8c` | `_AnoSDKInit` | SDK initialization entry point | High |
| `0x10febc` | `_AnoSDKSetUserInfo` | User information setup for monitoring | High |
| `0x10ffd0` | `_AnoSDKOnRecvData` | External data reception handler | High |
| `0x10ff58` | `_AnoSDKOnPause` | Background transition handler | Medium |
| `0x10ff78` | `_AnoSDKOnResume` | Foreground transition handler | Medium |
| `0x110028` | `_AnoSDKIoctl` | Privacy compliance control interface | High |

### 2: Initialization System

AnoSDK employs a sophisticated distributed initialization system with **51 separate initialization functions** (`InitFunc_0` to `InitFunc_50`), making analysis significantly more challenging, if you want to have a deeper analysis, you could contribute to this project. Here are a few function i can checked:

| Address | Function | Purpose | Concern Level |
|---------|----------|---------|---------------|
| `0x1ef30` | `InitFunc_0` | String Decryption Init - Initialize string decrypt system | High |
| `0x450cc` | `InitFunc_1` | Memory Management Init - Setup memory management | Medium |
| `0x6ec48` | `InitFunc_2` | Thread Management Init - Setup threading system | Medium |
| `0xa6e70` | `InitFunc_3` | Security Init - Initialize security subsystem | High |
| `0xab398` | `InitFunc_4` | Monitoring Init - Setup monitoring capabilities | High |
| `0xbfcd0` | `InitFunc_5` | Network Init - Initialize network communication | Medium |

```cpp
//initialization sequence
InitFunc_0  → String decryption system setup
InitFunc_1  → Memory management initialization  
InitFunc_2  → Threading system activation
InitFunc_3  → Security subsystem deployment
InitFunc_4  → Monitoring capabilities activation
// ... + 46 additional subsystems
```

---

## Obfuscation

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