use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_OPTIONAL_HEADER64};
use winapi::um::winnt::IMAGE_NT_HEADERS64;
use std::ffi::CStr;

fn main() {
    let base = unsafe {
        GetModuleHandleA(std::ptr::null())
    } as *const u8;

    println!("[*] Base address: {:p}", base);

    let dos_header = unsafe {
        &*(base as *const IMAGE_DOS_HEADER)
    };

    println!("[*] e_Magic:  0x{:X}", dos_header.e_magic);   // expect 0x5A4D
    println!("[*] e_lfanew: 0x{:X}", dos_header.e_lfanew);  // expect 0x100 or similar

    let nt_header = unsafe {
        &*(base.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64)
    };

    println!("[*] NT Headers is located at: {:p}", nt_header as *const _);
    println!("[*] NT HEADERS 64 Signature: 0x{:X}", nt_header.Signature);
    println!("[*] NT Optional HEADERS Magic: {:?}", nt_header.OptionalHeader.Magic);

    let data_directory = unsafe {
        nt_header.OptionalHeader.DataDirectory.as_ptr()
    };

    let import_dir = unsafe {
        &*(data_directory.add(1))
    };

    println!("[*] Virtual Address of Import Directory: 0x{:x}", import_dir.VirtualAddress);


    // pointer to first descriptor
    let mut desc_ptr = unsafe {
        base.add(import_dir.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR
    };

    loop {
        let desc = unsafe { &*desc_ptr };

        // null terminator — all fields zero means end of array
        if desc.Name == 0 {
            break;
        }

        // read the DLL name string (it's an RVA to a null-terminated ASCII string)
        let dll_name = unsafe {
            CStr::from_ptr(base.add(desc.Name as usize) as *const i8)
                .to_str()
                .unwrap_or("???")
        };

        println!("[*] DLL: {}", dll_name);

        let mut iat_ptr = unsafe{base.add(desc.FirstThunk as usize) as *const usize};
        let mut ilt_ptr =  unsafe{base.add(*desc.u.OriginalFirstThunk() as usize) as *const usize};


        unsafe {
            loop {
                let iat_entry = unsafe { *iat_ptr };
                let ilt_entry = unsafe { *ilt_ptr };

                if iat_entry == 0 { break; }

                // ILT entry points to IMAGE_IMPORT_BY_NAME
                // skip the 2-byte hint, name is at +2
                let name_ptr = base.add((ilt_entry & 0x7FFFFFFFFFFFFFFF) as usize + 2) as *const i8;
                let fn_name = unsafe { CStr::from_ptr(name_ptr).to_str().unwrap_or("???") };

                println!("    [+] 0x{:016X} -> {}", iat_entry, fn_name);

                // advance both pointers together
                iat_ptr = unsafe { iat_ptr.add(1) };
                ilt_ptr = unsafe { ilt_ptr.add(1) };
            }
        }

        // advance to next descriptor (20 bytes / 0x14)
        desc_ptr = unsafe { desc_ptr.add(1) };
    }


}