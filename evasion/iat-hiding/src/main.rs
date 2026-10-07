use std::{
    ffi::{CStr, CString}, ptr::null_mut
};

use winapi::{
    ctypes::c_void,
    um::{
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        winnt::{
            IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
            IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE,
        },
    },
};

fn get_proc_address_replacement(h_module: *mut c_void, lp_api_name: *const i8) -> *mut c_void {
    unsafe {
        let p_base = h_module as *mut i8;

        // get the dos header and doing the check !
        let p_img_dos_hdr = p_base as *const IMAGE_DOS_HEADER;

        if (*p_img_dos_hdr).e_magic != IMAGE_DOS_SIGNATURE {
            return null_mut();
        }

        // here we get the nt headers and verify the signature !
        let p_img_nt_hdrs =
            (p_base.wrapping_add((*p_img_dos_hdr).e_lfanew as usize)) as *const IMAGE_NT_HEADERS;

        if (*p_img_nt_hdrs).Signature != IMAGE_NT_SIGNATURE {
            return null_mut();
        }

        let img_opt_hdr = &(*p_img_nt_hdrs).OptionalHeader;

        let p_img_export_dir = (p_base.wrapping_add(
            img_opt_hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress
                as usize,
        )) as *const IMAGE_EXPORT_DIRECTORY;

        let function_name_array =
            (p_base.wrapping_add((*p_img_export_dir).AddressOfNames as usize)) as *const u32;
        let function_address_array =
            (p_base.wrapping_add((*p_img_export_dir).AddressOfFunctions as usize)) as *const u32;
        let function_ordinal_array =
            (p_base.wrapping_add((*p_img_export_dir).AddressOfNameOrdinals as usize)) as *const u16;

        let target_name = CStr::from_ptr(lp_api_name);

        // Just one small experimental thing. Find the Unique Functions !
        // // first get the size !
        // let export_dir_size = img_opt_hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size;

        // let mut unique_functions = HashSet::new();
        // for i in 0..(*p_img_export_dir).NumberOfFunctions {
        //     // get the func addr of RVA from AddrOfFunc
        //     let func_rva = *function_address_array.offset(i as isize);

        //     let func_addr = p_base.wrapping_add(func_rva as usize) as *mut c_void;

        //     let export_dir_start = p_img_export_dir as usize;
        //     let export_dir_end = export_dir_start + export_dir_size as usize;
        //     let func_addr_value = func_rva as usize + p_base as usize;

        //     if func_addr_value >= export_dir_start && func_addr_value < export_dir_end {
        //         continue;
        //     }
        //     unique_functions.insert(func_addr);
        // }
        // println!("Total exported functions: {}", (*p_img_export_dir).NumberOfFunctions);
        // println!("Unique functions (excluding forwarders): {}", unique_functions.len());



        for i in 0..(*p_img_export_dir).NumberOfFunctions {
            let p_function_name =
                p_base.wrapping_add(*function_name_array.offset(i as isize) as usize) as *const i8;
            let function_name = CStr::from_ptr(p_function_name);

            let ordinal = *function_ordinal_array.offset(i as isize);
            let p_function_addr = p_base
                .wrapping_add(*function_address_array.offset(ordinal as isize) as usize)
                as *mut c_void;

            println!("[{}] Function Name: {:?} - {:?} - Ordinal: {}", i ,function_name, p_function_addr, ordinal);

            if target_name == function_name {
                return p_function_addr;
            }
        }

        null_mut()
    }
}

fn main() {
    unsafe {
        let ntdll = CString::new("ntdll.dll").unwrap();
        let h_handle = GetModuleHandleA(ntdll.as_ptr());

        if h_handle.is_null() {
            println!("[-] Error getting Module");
            return;
        }

        let getprocaddr =
            GetProcAddress(h_handle, "NtAllocateVirtualMemory\0".as_ptr() as *const i8);

        println!("[+] Original GetProcAddress: {:?}", getprocaddr);

        let replacement_addr = get_proc_address_replacement(
            h_handle as *mut c_void,
            b"NtAllocateVirtualMemory\0".as_ptr() as *const i8,
        );

        println!("[+] GetProcAddress Replacement : {:?}", replacement_addr);
    }
}
