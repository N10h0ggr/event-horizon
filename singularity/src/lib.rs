#![no_std]

// 1. Module Declarations
mod logger;
mod raii;
mod ioctl;

extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;

use core::mem::MaybeUninit;
use wdk_alloc::WdkAllocator;
use wdk_sys::{DRIVER_OBJECT, DEVICE_OBJECT, IRP, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, STATUS_INVALID_DEVICE_REQUEST, IRP_MJ_CREATE, IRP_MJ_CLOSE, IRP_MJ_DEVICE_CONTROL, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, DO_BUFFERED_IO, UNICODE_STRING};
// User note: functions in ntddk
use wdk_sys::ntddk::{IoCreateDevice, IoCreateSymbolicLink, IofCompleteRequest, IoDeleteSymbolicLink, IoDeleteDevice, RtlInitUnicodeString};
use windows_sys::w;
use log::{info, error, warn};

// Defines the single source of truth for device naming.
const DEVICE_NAME: *const u16 = w!("\\Device\\SingularityDriver");
const DOS_DEVICE_NAME: *const u16 = w!("\\DosDevices\\SingularityDriver");

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

/// The entry point for the Windows Kernel Driver.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    // Initialize logging immediately
    if logger::init().is_err() {
        return STATUS_UNSUCCESSFUL;
    }
    info!("Singularity: DriverEntry called.");

    // Setup Dispatch Routines
    driver.DriverUnload = Some(driver_unload);
    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch_device_control);

    let mut dev_name: MaybeUninit<UNICODE_STRING> = MaybeUninit::zeroed();
    RtlInitUnicodeString(dev_name.as_mut_ptr(), DEVICE_NAME);
    let device_name = dev_name.assume_init();

    let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();

    // Create Device Object
    let status = IoCreateDevice(
        driver,
        0,
        dev_name.as_mut_ptr(),
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        0,
        &mut device_object,
    );

    if status != STATUS_SUCCESS {
        error!("Failed to create device object: {:#X}", status);
        return status;
    }

    // Initialize RAII Guard immediately after resource creation.
    let mut device_guard = raii::DeviceGuard::new(device_object);

    // Configure IO Flags
    // DO_BUFFERED_IO: The I/O manager copies user data to a system buffer. Safer for beginners.
    (*device_object).Flags |= DO_BUFFERED_IO;

    // Create Symbolic Link
    let mut dos_name: MaybeUninit<UNICODE_STRING> = MaybeUninit::zeroed();
    RtlInitUnicodeString(dos_name.as_mut_ptr(), DOS_DEVICE_NAME);
    let device_name = dos_name.assume_init();

    let status = IoCreateSymbolicLink(dos_name.as_mut_ptr(), dev_name.as_mut_ptr());

    if status != STATUS_SUCCESS {
        error!("Failed to create symbolic link: {:#X}", status);
        // device_guard will drop here, deleting the device_object automatically.
        return status;
    }

    // Register the link with the guard. If we fail after this point, the link acts as a cleanup target.
    device_guard.set_sym_link(DOS_DEVICE_NAME);

    // Enable Device
    (*device_object).Flags &= !wdk_sys::DO_DEVICE_INITIALIZING;

    // Success! Defuse the guard so resources persist.
    device_guard.defuse();

    info!("Driver initialized successfully.");
    STATUS_SUCCESS
}

/// Clean up resources when the driver is stopped.
pub extern "C" fn driver_unload(driver: *mut DRIVER_OBJECT) {
    info!("Singularity: DriverUnload called.");
    unsafe {
        let mut dos_name: MaybeUninit<UNICODE_STRING> = MaybeUninit::zeroed();
        RtlInitUnicodeString(dos_name.as_mut_ptr(), DOS_DEVICE_NAME);
        let device_name = dos_name.assume_init();

        let status: NTSTATUS = IoDeleteSymbolicLink(dos_name.as_mut_ptr());
        if status != STATUS_SUCCESS {
            warn!("Failed to delete symbolic link!");
        };

        if !(*driver).DeviceObject.is_null() {
            IoDeleteDevice((*driver).DeviceObject);
        }
    }
}

/// Handles Create (Opening handle) and Close (Closing handle) requests.
pub unsafe extern "C" fn dispatch_create_close(
    _device: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    // Just complete successfully. We don't need per-handle context for this driver.
    (*irp).IoStatus.Information = 0;
    (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
    IofCompleteRequest(irp, wdk_sys::IO_NO_INCREMENT as i8);
    STATUS_SUCCESS
}

/// Central router for Device Control (IOCTL) requests.
pub unsafe extern "C" fn dispatch_device_control(
    _device: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let stack = ioctl::get_irp_stack_location(irp);
    let control_code = (*stack).Parameters.DeviceIoControl.IoControlCode;

    // Route based on IOCTL code
    let status = match control_code {
        shared::IOCTL_SET_PROCESS_PPL => {
            ioctl::handle_ppl_request(irp, stack)
        },
        _ => {
            error!("Unknown IOCTL code: {:#X}", control_code);
            STATUS_INVALID_DEVICE_REQUEST
        }
    };

    // Complete the IRP
    (*irp).IoStatus.Information = 0; // No bytes returned for this specific IOCTL
    (*irp).IoStatus.__bindgen_anon_1.Status = status;
    IofCompleteRequest(irp, wdk_sys::IO_NO_INCREMENT as i8);
    status
}