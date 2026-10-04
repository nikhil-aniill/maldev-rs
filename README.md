# maldev-rs

![Progress](https://img.shields.io/badge/MDA_Progress-48%2F180_modules-yellow?style=flat-square)

A research repository of Windows offensive security and malware development techniques implemented in Rust.

> **Disclaimer:** This repository is intended for authorized security research, red team operations, CTF competitions, and educational purposes only. All techniques documented here are drawn from public security research. Do not use these implementations against systems you do not own or have explicit written permission to test.

working through **maldev academy** (180 modules) and completing the Objectives in Rust.

not an expert. still figuring things out.

---

## what i'm building

![maldev-rs](https://img.shields.io/badge/maldev--rs-Rust-orange?style=flat-square&logo=rust)
![status](https://img.shields.io/badge/status-learning-yellow?style=flat-square)
![mde](https://img.shields.io/badge/tested%20against-MDE%20P2-5c2d91?style=flat-square&logo=microsoftdefender)

a Rust repo where i reimplement MDA techniques as i learn them.
each folder has the code + notes on what MDE detected vs missed.

[→ maldev-rs](https://github.com/nikhil-aniill/maldev-rs)

---

## progress through maldev academy

| area | modules | status |
|------|---------|--------|
| PE header parsing & string hashing | 47–48 | ✅ done  |
| IAT hiding & API hashing | 49–56, 79 | 🔄 in progress |
| API hooking | 57–61 | ⬜ upcoming |
| Syscalls (Hell's Gate, HellsHall, indirect) | 62–68, 87–88 | ⬜ upcoming |
| Anti-analysis & anti-debug | 69–77, 124 | ⬜ upcoming |
| NTDLL unhooking | 82–86 | ⬜ upcoming |
| ETW bypass | 102–107 | ⬜ upcoming|
| AMSI bypass | 108–110 |⬜ upcoming |
| Process injection (APC, hollowing, stomping…) | 45–46, 118–135 | ⬜ upcoming |
| Sleep obfuscation (Ekko, Zilean, Foliage) | 143–146, 149 | ⬜ upcoming |
| C2 integration & BOFs | 112–113, 139–141 | ⬜ upcoming |
| Credential dumping | 160–168 | ⬜ upcoming |
| Persistence | 173–180 | ⬜ upcoming |

## Techniques

| Category | Technique | MDE Detection | Notes |
|---|---|---|---|
| process-injection | ppid-spoofing | THE MDE detection didn't go off due to lack of payload | |
| process-injection | process-argument-spoofing | | |
| process-injection | apc-injection | | |
| process-injection | local-mapping-injection | | |
| process-injection | threadless-injection | | |
| process-injection | module-stomping | | |
| process-injection | module-overloading | | |
| process-injection | process-hollowing | | |
| process-injection | ghost-process-injection | | |
| process-injection | ghostly-hollowing | | |
| process-injection | herpaderping | | |
| process-injection | herpaderply-hollowing | | |
| process-injection | srdi | | |
| process-injection | cross-architecture-injection | | |
| process-injection | knowndll-cache-poisoning | | |
| process-injection | local-pe-injection | | |
| process-injection | reflective-dll-injection | | |
| process-injection | process-hypnosis | | |
| process-injection | pefluctuation | | |
| process-injection | fibers-payload-execution | | |
| evasion | iat-hiding | | |
| evasion | api-hashing | | |
| evasion | compile-time-api-hashing | | |
| evasion | iat-camouflage | | |
| evasion | block-dll-policy | | |
| evasion | binary-entropy-reduction | | |
| evasion | binary-metadata-modification | | |
| evasion | crt-library-removal | | |
| evasion | file-bloating | | |
| evasion | malware-directory-placement | | |
| evasion | dll-sideloading | | |
| evasion | byovd | | |
| evasion | library-proxy-loading | | |
| syscalls | userland-hooking | | |
| syscalls | syswhispers | | |
| syscalls | hells-gate | | |
| syscalls | hellshall-indirect-syscalls | | |
| syscalls | tampered-syscalls-via-hbps | | |
| syscalls | reimplementing-classic-injection-via-syscalls | | |
| syscalls | reimplementing-mapping-injection-via-syscalls | | |
| syscalls | reimplementing-apc-injection-via-syscalls | | |
| anti-analysis | anti-debugging | | |
| anti-analysis | self-deletion | | |
| anti-analysis | anti-vm | | |
| anti-analysis | delay-execution | | |
| anti-analysis | api-hammering | | |
| anti-analysis | brute-force-decryption | | |
| anti-analysis | tls-callbacks | | |
| anti-analysis | hbp-hooking | | |
| anti-analysis | hbp-credential-dumping | | |
| anti-analysis | patchless-threadless | | |
| etw | etw-introduction | | |
| etw | etw-byte-patching | | |
| etw | etw-improved-patching | | |
| etw | patchless-etw-via-hbps | | |
| etw | etw-provider-session-hijacking | | |
| amsi | amsi-byte-patching | | |
| amsi | amsi-via-hbps | | |
| api-hooking | detours | | |
| api-hooking | minhook | | |
| api-hooking | custom-code | | |
| api-hooking | using-windows-apis | | |
| ntdll-unhooking | from-disk | | |
| ntdll-unhooking | from-knowndlls | | |
| ntdll-unhooking | from-suspended-process | | |
| ntdll-unhooking | from-web-server | | |
| sleep-obfuscation | ekko | | |
| sleep-obfuscation | zilean | | |
| sleep-obfuscation | foliage | | |
| sleep-obfuscation | ekko-with-stack-spoofing | | |
| sleep-obfuscation | heap-encryption-with-ekko | | |
| pe-utils | pe-header-parsing | | |
| pe-utils | pe-packer | | |
| pe-utils | string-hashing | | |
| pe-utils | custom-winapi-functions | | |
| pe-utils | ntcreateuserprocess | | |
| pe-utils | thread-enumeration | | |
| credential-dumping | lsass-handle-ppl-bypass | | |
| credential-dumping | handle-duplication | | |
| credential-dumping | rtlreportsilentprocessexit | | |
| credential-dumping | seclogon-race-condition | | |
| credential-dumping | sam-database-local | | |
| credential-dumping | sam-database-remote | | |
| credential-dumping | sam-database-disk | | |
| credential-dumping | domain-enumeration-ms-samr | | |
| browser-dumping | firefox-cookies | | |
| browser-dumping | firefox-logins | | |
| browser-dumping | chrome-cookies | | |
| browser-dumping | chrome-logins | | |
| persistence | registry | | |
| persistence | file-system | | |
| persistence | windows-services | | |
| persistence | scheduled-tasks | | |
| persistence | wmi | | |
| persistence | com-hijacking | | |
| persistence | electron-apps | | |
| encoders-crypto | basen-encoder-decoder | | |
| encoders-crypto | xor | | |
| encoders-crypto | aes | | |
| encoders-crypto | rc4 | | |
| c2 | havoc-integration | | |
| c2 | dll-payload-loader | | |
| c2 | bof-writing-and-loading | | |
| c2 | dotnet-assembly-execution | | |
| c2 | keylogger-remote-exfil | | |
| c2 | screenshot-capture | | |
| c2 | token-manipulation | | |
| exploiting-edrs | edr-evasion-via-exploitation | | |
| exploiting-edrs | edr-lolbins | | |
| exploiting-edrs | internal-exclusion-list | | |
| exploiting-edrs | preventing-edr-action | | |
