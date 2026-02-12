#![no_std]

use windows_sys::Win32::System::Ioctl::{FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED};

/// The explicit definition for the IOCTL macro since it's not exported directly
/// as a function in windows-sys for compile-time constants in the same way C macros work.
///
/// Formula: (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
macro_rules! CTL_CODE {
    ($DeviceType:expr, $Function:expr, $Method:expr, $Access:expr) => {
        ($DeviceType << 16) | ($Access << 14) | ($Function << 2) | $Method
    };
}

/// The unique IOCTL code to trigger the integrity level change.
///
/// - Device: Unknown
/// - Function: 0x800
/// - Method: Buffered
/// - Access: Any
pub const IOCTL_SET_PROCESS_PPL: u32 =
    CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// The structure sent from the user-mode application to the driver.
#[repr(C)]
pub struct ProcessProtectionRequest {
    /// The Process ID (PID) of the target process to modify.
    pub target_pid: u32,
}
