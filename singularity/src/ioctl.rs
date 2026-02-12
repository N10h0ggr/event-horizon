#![no_std]

use wdk_sys::{IO_STACK_LOCATION, IRP, NTSTATUS, PEPROCESS};
use wdk_sys::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
// User note: using ntddk for functions
use log::{error, info};
use shared::ProcessProtectionRequest;
use wdk_sys::ntddk::{ObfDereferenceObject, PsLookupProcessByProcessId};

/// WARNING: This changes between Windows versions.
/// Windows 11 24H2 (26100.1) EPROCESS->Protection offset is 0x5FA
const EPROCESS_PROTECTION_OFFSET: usize = 0x5FA;

/// PPL-Antimalware (Signer: 3, Type: 1) => 0011 0001 => 0x31
const PPL_ANTIMALWARE_VALUE: u8 = 0x31;

/// Helper to get the current stack location from an IRP.
///
/// # Why
/// This function is usually an inline C macro (`IoGetCurrentIrpStackLocation`).
/// Since it's not exported by wdk_sys, we implement the pointer arithmetic manually here.
#[inline(always)]
pub const unsafe fn get_irp_stack_location(irp: *mut IRP) -> *mut IO_STACK_LOCATION {
    (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation
}

/// Handler for the PPL Modification IOCTL.
///
/// # Safety
/// Validates input size, but performs raw memory writes to kernel structures (DKOM).
pub unsafe fn handle_ppl_request(irp: *mut IRP, stack: *mut IO_STACK_LOCATION) -> NTSTATUS {
    let input_len = (*stack).Parameters.DeviceIoControl.InputBufferLength;
    let expected_len = core::mem::size_of::<ProcessProtectionRequest>();

    // Validation
    if (input_len as usize) != expected_len {
        error!(
            "Singularity: [IOCTL] Size mismatch. Got {}, expected {}",
            input_len, expected_len
        );
        return STATUS_INVALID_PARAMETER;
    }

    let buffer = (*irp).AssociatedIrp.SystemBuffer;
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Data Extraction
    let request = &*(buffer as *const ProcessProtectionRequest);
    info!(
        "Singularity: [IOCTL] Requesting PPL change for PID: {}",
        request.target_pid
    );

    // Execution
    perform_dkom_ppl(request.target_pid)
}

/// The core DKOM logic.
/// Separated from the IRP handling to make it testable or reusable internally.
unsafe fn perform_dkom_ppl(pid: u32) -> NTSTATUS {
    let mut process: PEPROCESS = core::ptr::null_mut();

    // Look up the EPROCESS object. This increments the reference count.
    let status = PsLookupProcessByProcessId(pid as _, &mut process);
    if status != STATUS_SUCCESS {
        error!(
            "Singularity: [DKOM] Failed to lookup PID {}: {:#X}",
            pid, status
        );
        return status;
    }

    // We cast the opaque pointer to a byte pointer to do arithmetic.
    // SAFETY: This can make the machine crash if EPROCESS_PROTECTION_OFFSET
    //         is not correctly set up
    let process_base = process as *mut u8;
    let protection_addr = process_base.add(EPROCESS_PROTECTION_OFFSET);

    let old_value = *protection_addr;
    *protection_addr = PPL_ANTIMALWARE_VALUE;

    info!(
        "Singularity: [DKOM] Success. PID: {} | Offset: {:#X} | Old: {:#02X} -> New: {:#02X}",
        pid, EPROCESS_PROTECTION_OFFSET, old_value, PPL_ANTIMALWARE_VALUE
    );

    // Always dereference the object when done to prevent memory leaks.
    ObfDereferenceObject(process as _);

    STATUS_SUCCESS
}
