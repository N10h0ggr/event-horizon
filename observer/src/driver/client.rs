use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::ptr;

use shared::{IOCTL_SET_PROCESS_PPL, ProcessProtectionRequest};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

// The user-mode path to the symbolic link created by the driver.
// \DosDevices\SingularityDriver -> \\.\SingularityDriver
const DEVICE_PATH: *const u16 = windows_sys::w!(r"\\.\SingularityDriver");

/// Connects to the Singularity Driver and requests a PPL upgrade for the target PID.
///
/// # Arguments
/// * `pid` - The Process ID of the target process (e.g., the current process).
///
/// # Returns
/// * `Ok(())` if the driver accepted and processed the request.
/// * `Err(std::io::Error)` if the driver could not be opened or the IOCTL failed.
pub fn set_process_ppl(pid: u32) -> io::Result<()> {
    // Open a handle to the driver
    // We need GENERIC_READ | GENERIC_WRITE to send IOCTLs, even if FILE_ANY_ACCESS is used.
    let handle = unsafe {
        CreateFileW(
            DEVICE_PATH,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(), // Security attributes
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0 as HANDLE,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    // Prepare the Input Data
    let mut request = ProcessProtectionRequest { target_pid: pid };

    // Send the IOCTL
    let mut bytes_returned: u32 = 0;
    let success = unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
            handle,
            IOCTL_SET_PROCESS_PPL,
            &mut request as *mut _ as *mut c_void, // Input Buffer
            size_of::<ProcessProtectionRequest>() as u32,
            ptr::null_mut(), // Output Buffer (Not used)
            0,               // Output Buffer Size
            &mut bytes_returned,
            ptr::null_mut(), // Overlapped (Synchronous call)
        )
    };

    if success == 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }

    Ok(())
}
