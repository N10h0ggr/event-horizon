use core::mem::{MaybeUninit, ManuallyDrop};
use wdk_sys::{
    DEVICE_OBJECT, NTSTATUS, UNICODE_STRING,
};
use wdk_sys::ntddk::{IoDeleteDevice, IoDeleteSymbolicLink, RtlInitUnicodeString};

/// A scope guard for Driver Entry initialization.
///
/// # Why
/// Ensures resources (Device Object, Symbolic Link) are released if `DriverEntry`
/// returns an error partway through.
pub struct DeviceGuard {
    // We hold the raw pointer. If it is null, we assume it's already cleaned or invalid.
    device_object: *mut DEVICE_OBJECT,
    sym_link_name: Option<*const u16>,
}

impl DeviceGuard {
    pub fn new(device_object: *mut DEVICE_OBJECT) -> Self {
        Self {
            device_object,
            sym_link_name: None,
        }
    }

    /// Registers the symbolic link for cleanup.
    ///
    /// # Safety
    /// `name` must point to a valid, null-terminated UTF-16 string that lives
    /// as long as this guard (typically a 'static constant).
    pub fn set_sym_link(&mut self, name: *const u16) {
        self.sym_link_name = Some(name);
    }

    /// Consumes the guard, preventing the cleanup logic from running.
    /// This is called only when `DriverEntry` fully succeeds.
    pub fn defuse(self) {
        let _ = ManuallyDrop::new(self);
    }
}

impl Drop for DeviceGuard {
    fn drop(&mut self) {
        unsafe {
            // Cleanup Symbolic Link (if registered)
            if let Some(name_ptr) = self.sym_link_name {
                // We must reconstruct the UNICODE_STRING struct to pass to IoDeleteSymbolicLink.
                // This is safe because the string literal is static.
                let mut unicode_name: MaybeUninit<UNICODE_STRING> = MaybeUninit::zeroed();
                RtlInitUnicodeString(unicode_name.as_mut_ptr(), name_ptr);

                let _ = IoDeleteSymbolicLink(unicode_name.as_mut_ptr());
                log::warn!("DeviceGuard: Cleaned up symbolic link due to error.");
            }

            // Cleanup Device Object (always present in this design)
            if !self.device_object.is_null() {
                IoDeleteDevice(self.device_object);
                log::warn!("DeviceGuard: Cleaned up device object due to error.");
            }
        }
    }
}