use ntapi::ntpebteb::PEB;
use ntapi::{ntldr::LDR_DATA_TABLE_ENTRY, ntpsapi::PEB_LDR_DATA};
use std::arch::asm;
use std::ffi::{CStr, CString};
use std::io::Read;
use std::ptr::{null, null_mut};
use winapi::shared::ntdef::LIST_ENTRY;
use winapi::{
    shared::{
        minwindef::{DWORD, FARPROC, HMODULE},
        ntdef::PVOID,
        windef::HWND,
    },
    um::{
        errhandlingapi::GetLastError,
        libloaderapi::LoadLibraryA,
        winnt::{
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS,
            IMAGE_NT_SIGNATURE,
        },
        winuser::{MB_ICONEXCLAMATION, MB_OK},
    },
};

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: u16 = 0;

macro_rules! get_peb {
    () => {{
        #[cfg(target_pointer_width = "64")]
        {
            let gs: u64;
            asm!("mov {}, gs:0x60", out(reg) gs);
            gs as *const PEB
        }
        #[cfg(target_pointer_width = "32")]
        {
            let fs: u32;
            asm!("mov {}, fs:0x30", out(reg) fs);
            fs as *const PEB
        }
    }};
}

const INITIAL_SEED: u32 = 7;

unsafe fn hash_string_fnv1a(string: * const i8) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET_BASIS;
    let mut ptr = string;
    while *ptr != 0 {
        hash ^= *ptr as u8 as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
        ptr = ptr.add(1);
    }

    hash
}

macro_rules! hasha {
    ($api:expr) => {
        hash_string_fnv1a($api as *const i8)
    };
}

fn get_proc_address_h(h_module: HMODULE, dw_api_name_hash: u32) -> FARPROC {
    unsafe {

        if h_module.is_null() || dw_api_name_hash == 0 {
            return null_mut();
        }

        let p_base = h_module as *mut u8;
        let p_img_dos_hdr = p_base as *const IMAGE_DOS_HEADER;

        if (*p_img_dos_hdr).e_magic != IMAGE_DOS_SIGNATURE {
            return null_mut();
        }

        let p_img_nt_hdrs =
            p_base.wrapping_add((*p_img_dos_hdr).e_lfanew as usize) as *const IMAGE_NT_HEADERS;

        if (*p_img_nt_hdrs).Signature != IMAGE_NT_SIGNATURE {
            return null_mut();
        }


        let img_opt_hdr = &(*p_img_nt_hdrs).OptionalHeader;
        let p_img_export_dir = p_base.wrapping_add(
            img_opt_hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress
                as usize,
        ) as *const IMAGE_EXPORT_DIRECTORY;

        let function_name_array =
            p_base.wrapping_add((*p_img_export_dir).AddressOfNames as usize) as *const DWORD;

        let function_address_array =
            p_base.wrapping_add((*p_img_export_dir).AddressOfFunctions as usize) as *const DWORD;

        let function_ordinal_array =
            p_base.wrapping_add((*p_img_export_dir).AddressOfNameOrdinals as usize) as *const u16;

        for i in 0..(*p_img_export_dir).NumberOfFunctions {
            let p_function_name =
                p_base.wrapping_add(*function_name_array.add(i as usize) as usize) as *const i8;
            let ordinal = *function_ordinal_array.add(i as usize) as usize;
            let p_function_address =
                p_base.wrapping_add(*function_address_array.add(ordinal) as usize) as PVOID;
            if dw_api_name_hash == hasha!(p_function_name) {
                return p_function_address as FARPROC;
            }
        }
        null_mut()
    }
}

fn get_module_handle_h(dw_module_name_hash: u32) -> HMODULE {
    unsafe {
        let ppeb = get_peb!();
        if ppeb.is_null() {
            return null_mut();
        }

        let p_ldr = (*ppeb).Ldr as *mut PEB_LDR_DATA;
        if p_ldr.is_null() {
            return null_mut();
        }

        let list_head = &(*p_ldr).InLoadOrderModuleList as *const LIST_ENTRY;
        let mut p_dte = (*p_ldr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

        while p_dte as *const LIST_ENTRY != list_head && !p_dte.is_null() {
            if !(*p_dte).BaseDllName.Buffer.is_null()
                && (*p_dte).BaseDllName.Length != 0
                && (*p_dte).BaseDllName.Length < 260 {

                let wchars = std::slice::from_raw_parts(
                    (*p_dte).BaseDllName.Buffer,
                    (*p_dte).BaseDllName.Length as usize / 2,
                );

                let mut upper_case_dll_name = [0u8; 260];
                let mut i = 0;
                for &wchar in wchars {
                    upper_case_dll_name[i] = if wchar <= 0x7F {
                        (wchar as u8).to_ascii_uppercase()
                    } else {
                        0
                    };
                    i += 1;
                }
                upper_case_dll_name[i] = 0;

                // Compare hashes
                if hasha!(upper_case_dll_name.as_ptr() as *const i8) == dw_module_name_hash {
                    return (*p_dte).DllBase as HMODULE;
                }
            }
            p_dte = (*p_dte).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
        }

        null_mut()
    }
}



type FnMessageBoxA = unsafe extern "system" fn(HWND, *const i8, *const i8, u32) -> i32;

const USER32DLL_HASH: u32 = 0x1A58C439;
const MESSAGEBOXA_HASH: u32 = 0x23A979E4;

fn main() {
    unsafe {

        let user32_str = CString::new("USER32.DLL").unwrap();

        let user32_str = user32_str.as_ptr();
        if LoadLibraryA(user32_str).is_null() {
            println!("[!] LoadLibraryA Failed With Error: {}", GetLastError());
            return;
        }

        println!("[+] Hash of User32.dll is : 0x{:X}", hasha!(user32_str as *const i8));

        let h_user32_module = get_module_handle_h(USER32DLL_HASH);
        if h_user32_module.is_null() {
            println!("[!] Couldn't Get Handle To USER32.DLL");
            return;
        }

        let messageboxa_str = CString::new("MessageBoxA").unwrap();
        println!("[+] Hash of MessageBoxA is : 0x{:X}", hasha!(messageboxa_str.as_ptr()));
        let p_message_box_a = get_proc_address_h(h_user32_module, MESSAGEBOXA_HASH);

        if p_message_box_a.is_null() {
            println!("[!] Couldn't Find Address Of Specified Function");
            return;
        }

        let message_box_a: FnMessageBoxA = std::mem::transmute(p_message_box_a);
        message_box_a(
            null_mut(),
            "Building Maldev with MaldevAcademy\0".as_ptr() as *const i8,
            "Wow\0".as_ptr() as *const i8,
            MB_OK | MB_ICONEXCLAMATION,
        );

        println!("[+] Press <Enter> to Quit ...");
        let _ = std::io::stdin().read(&mut [0u8; 1]).unwrap();

    }
}
