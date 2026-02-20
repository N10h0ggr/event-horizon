use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::detect::errors::DetectionError;
use crate::etw::Event;

const PROCESS_RIGHTS: u32 = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
const ALLOWED_MODULES: [&str; 4] = ["ntdll.dll", "win32u.dll", "wow64win.dll", "kernelbase.dll"];

pub fn direct_syscalls(event: &Event) -> Result<Option<u64>, DetectionError> {
    // 1. Remove the kernel addresses from the call stack
    // 2. Get the module name that owns that memory address to do trigger alerts on
    //    modules such as ntdll.dll For this we need a handle to the target process

    let handle: HANDLE = unsafe { OpenProcess(PROCESS_RIGHTS, 0, event.pid()) };
    if handle.is_null() {
        let error_code = unsafe { GetLastError() };

        if error_code == ERROR_ACCESS_DENIED {
            log::debug!(
                "Access Denied for PID {}. Skipping stack analysis for protected process.",
                event.pid()
            );
            return Ok(None);
        }

        log::error!("OpenProcess failed for PID {}: {}", event.pid(), error_code);
        return Err(DetectionError::WindowsError(error_code));
    }

    let mut stack: Vec<u64> = event.stack_trace();
    if stack.is_empty() {
        return Err(DetectionError::DirectSyscalls(
            "Recieved empty stack trace".to_string(),
        ));
    }

    crate::detect::utils::filter_kernel_addresses(&mut stack);
    for address in stack {
        let module_name: String =
            crate::detect::utils::get_module_name_from_address(handle, address)?.to_lowercase();

        if !ALLOWED_MODULES.contains(&module_name.as_str()) {
            log::info!(
                "Direct Syscall detected! PID: {} | Module: {} | Address: {:#X}",
                event.pid(),
                module_name,
                address
            );
            return Ok(Some(address));
        }
    }

    let _ = unsafe { CloseHandle(handle) };

    Ok(None)
}
