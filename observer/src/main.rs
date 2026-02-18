use std::ffi::c_void;
use std::ptr::{null, null_mut};
use log;
use windows_sys::Win32::System::Threading::{
    CreateThread, GetCurrentProcessId, WaitForSingleObject
};


mod etw;
use etw::filter;
use etw::utils::guid_to_string;

const MICROSOFT_WINDOWS_KERNEL_AUDIT_API_CALLS: &str = "E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23";
const MICROSOFT_WINDOWS_THREAT_INTEL: &str = "F4E1897C-BB5D-5668-F1D8-040F4D8DD344";
const EVENTID_OPENTHREAD: u16 = 4;
const EVENTID_SETTHREADCONTEXT: u16 = 6;

const EVENT_ENABLE_PROPERTY_STACK_TRACE: u32 = 4; 


// This function is passed to a trampoline function that matches the needed C
// structure and parses the EVENT_RECORD using the provider schema or TDH
fn syscall_detection_callback(event: &etw::Event) {
    // 1. Get Current Process ID to skip our own events
    let current_pid: u32 = unsafe { GetCurrentProcessId() };

    if event.pid() == current_pid {
        return;
    }

    // 2. Match Event ID based on the provided Manifest
    // We parse specific fields known to exist for these IDs.
    match event.id() {
        // Event 4: OpenThread (or similar) - Manifest shows only ReturnCode
        4 => {
            log::info!("[Event 4] Detected from PID: {}", event.pid());
            if let Ok(ret) = event.get_property("ReturnCode") {
                log::debug!("  -> ReturnCode: {}", ret);
            }
        },
        // Event 5: OpenProcess - TargetProcessId, DesiredAccess, ReturnCode
        5 => {
            log::info!("[Event 5] OpenProcess Detected from PID: {}", event.pid());
            if let Ok(target_pid) = event.get_property("TargetProcessId") {
                log::info!("  -> Target PID: {}", target_pid);
            }
            if let Ok(access) = event.get_property("DesiredAccess") {
                log::info!("  -> Desired Access: {}", access);
            }
            if let Ok(ret) = event.get_property("ReturnCode") {
                log::debug!("  -> ReturnCode: {}", ret);
            }
        },
        // Event 6: SetThreadContext - TargetProcessId, TargetThreatId, DesiredAccess
        6 => {
            log::info!("[Event 6] SetThreadContext Detected from PID: {}", event.pid());
            if let Ok(target_pid) = event.get_property("TargetProcessId") {
                log::info!("  -> Target PID: {}", target_pid);
            }
            // Note: Manifest output listed this as "TargetThreatId" (likely a Windows typo),
            // so we must use that exact string key.
            if let Ok(target_tid) = event.get_property("TargetThreatId") {
                log::info!("  -> Target TID: {}", target_tid);
            }
            if let Ok(access) = event.get_property("DesiredAccess") {
                log::info!("  -> Desired Access: {}", access);
            }
            if let Ok(ret) = event.get_property("ReturnCode") {
                log::debug!("  -> ReturnCode: {}", ret);
            }
        },
        // Handle other IDs generic logging if needed
        id => {
            log::debug!("Event ID {} detected from PID: {}", id, event.pid());
        }
    }

    // 3. Process Stack Trace
    let stack = event.stack_trace();
    if stack.is_empty() {
        return;
    }

    log::trace!("  -> Stack Trace ({} frames):", stack.len());
    for (i, addr) in stack.iter().enumerate() {
        log::trace!("     [{}] {:#x}", i, addr);
    }
}

// This matches: pub unsafe extern "system" fn(lpthreadparameter: *mut c_void) -> u32
unsafe extern "system" fn event_loop_entry(user_trace_ptr: *mut c_void) -> u32 {
    // Cast the void pointer back to the Rust reference
    let user_trace = unsafe { &*(user_trace_ptr as *const etw::UserTrace) };
    user_trace.start()
}

// TODO: Add proper return type for Windows
fn main() {

    env_logger::init();

    // Define the Session (User or Kernel)
    let mut user_trace = etw::UserTrace::new("Syscalls-Detector");

    // Define the Provider
    let mut provider = etw::Provider::new(MICROSOFT_WINDOWS_KERNEL_AUDIT_API_CALLS)
        .trace_flags(EVENT_ENABLE_PROPERTY_STACK_TRACE);

    provider.load_manifest().expect("Failed to load provider manifest");
    if let Some(manifest) = &provider.manifest {
        log::trace!("Provider manifest: {:?}", manifest);
    }

    let mut filter_open_thread = etw::EventFilter::new(filter::DoesMatch(EVENTID_OPENTHREAD));
    let mut filter_set_context_threat = etw::EventFilter::new(filter::DoesMatch(EVENTID_SETTHREADCONTEXT));

    filter_open_thread.add_callback(syscall_detection_callback);
    filter_set_context_threat.add_callback(syscall_detection_callback);

    provider.add_filter(filter_open_thread);
    provider.add_filter(filter_set_context_threat);

    log::debug!("Enabling provider {}: {}", provider.name, guid_to_string(&provider.guid));

    user_trace.enable(provider).unwrap();

    // pub unsafe extern "system" fn CreateThread(
    //     lpthreadattributes: *const SECURITY_ATTRIBUTES,
    //     dwstacksize: usize,
    //     lpstartaddress: LPTHREAD_START_ROUTINE,
    //     lpparameter: *const c_void,
    //     dwcreationflags: THREAD_CREATION_FLAGS,
    //     lpthreadid: *mut u32,
    // ) -> HANDLE
    let trace_thread_handle = unsafe {
        CreateThread(
            null(),
            0,
            Some(event_loop_entry),
            &mut user_trace as *mut _ as *mut c_void,
            0,
            null_mut(),
        )
    };

    if trace_thread_handle.is_null() {
        return;
    }

    // pub unsafe extern "system" fn WaitForSingleObject(
    //     hhandle: HANDLE,
    //     dwmilliseconds: u32,
    // ) -> WAIT_EVENT
    unsafe { WaitForSingleObject(trace_thread_handle, 10000) };
    user_trace.stop();
}


