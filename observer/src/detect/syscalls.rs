use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::detect::errors::DetectionError;
use crate::etw::Event;

const PROCESS_RIGHTS: u32 = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

const ALLOWED_MODULES: [&str; 6] = [
    "ntdll.dll",
    "win32u.dll",
    "wow64win.dll",
    "wow64.dll",
    "wow64cpu.dll",
    "kernelbase.dll",
];

// TODO: Change the return for a data structure representing an Alert.
pub fn direct_syscalls(event: &Event) -> Result<Option<u64>, DetectionError> {
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
        let _ = unsafe { CloseHandle(handle) };
        return Err(DetectionError::DirectSyscalls(
            "Received empty stack trace".to_string(),
        ));
    }

    crate::detect::utils::filter_kernel_addresses(&mut stack);

    let mut detected_address: Option<u64> = None;

    if let Some(&top_user_address) = stack.first() {
        match crate::detect::utils::get_module_name_from_address(handle, top_user_address) {
            Ok(module_name) => {
                let module_lower = module_name.to_lowercase();

                if !ALLOWED_MODULES.contains(&module_lower.as_str()) {
                    log::info!(
                        "Direct Syscall detected! PID: {} | Module: {} | Address: {:#X}",
                        event.pid(),
                        module_name,
                        top_user_address
                    );
                    detected_address = Some(top_user_address);
                }
            }
            Err(e) => {
                // Address could not be resolved, therefore memory is not mapped to disk and is
                // in-memory execution. This can be due to malicious behavior (injected shellcode,
                // PE reflection, etc.) or benign pertaining to JIT compilers and managed runtimes.
                //
                // TODO: To filter out known benign false positives, the following should be implemented:
                // 1. Runtime / Module Profiling: Check if the target process has loaded known JIT
                //    engines (e.g., 'coreclr.dll' / 'clr.dll' for .NET, 'v8.dll' for Chromium/Edge,
                //    'jvm.dll' for Java, or 'mscorlib.dll').
                // 2. Process Whitelisting: Correlate the PID with expected heavy JIT processes
                //    (e.g., chrome.exe, msedge.exe, java.exe, w3wp.exe). Legitimate EDRs and Antivirus
                //    solutions sometimes allocate anonymous executable memory for API hooking trampolines.
                //    Whitelisting by digital signature or known EDR process names is required.
                log::warn!(
                    "Syscall from unbacked memory / anonymous region detected! PID: {} | Address: {:#X} | Error: {:?}",
                    event.pid(),
                    top_user_address,
                    e
                );
            }
        }
    }

    let _ = unsafe { CloseHandle(handle) };

    Ok(detected_address)
}
