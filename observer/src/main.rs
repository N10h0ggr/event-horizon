use log;
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use windows_sys::Win32::System::Threading::{
    CreateThread, GetCurrentProcessId, WaitForSingleObject,
};

mod etw;
use etw::filter;
use etw::utils::guid_to_string;

mod detect;

const MICROSOFT_WINDOWS_KERNEL_AUDIT_API_CALLS: &str = "E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23";
const MICROSOFT_WINDOWS_THREAT_INTEL: &str = "F4E1897C-BB5D-5668-F1D8-040F4D8DD344";

const EVENTID_OPENTHREAD: u16 = 4;
const EVENTID_SETTHREADCONTEXT: u16 = 6;

const EVENT_ENABLE_PROPERTY_STACK_TRACE: u32 = 4;

// This function is passed to a trampoline function that matches the needed C
// structure and parses the EVENT_RECORD using the provider schema or TDH
fn syscall_detection_callback(event: &etw::Event) {
    let current_pid: u32 = unsafe { GetCurrentProcessId() };
    // Skip current process
    if event.pid() == current_pid {
        return;
    }

    // We parse specific fields known to exist for these IDs.
    match event.id() {
        EVENTID_OPENTHREAD => {
            log::trace!("[Event 4] OpenThread Detected from PID: {}", event.pid());

            let _address = match detect::direct_syscalls(&event) {
                Ok(option_address) => option_address,
                Err(_e) => None,
            };
        }
        // Handle other IDs generic logging if needed
        id => {
            log::debug!("Event ID {} detected from PID: {}", id, event.pid());
        }
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

    provider
        .load_manifest()
        .expect("Failed to load provider manifest");
    if let Some(manifest) = &provider.manifest {
        log::trace!("Provider manifest: {:?}", manifest);
    }

    let mut filter_open_thread = etw::EventFilter::new(filter::DoesMatch(EVENTID_OPENTHREAD));
    let mut filter_set_context_threat =
        etw::EventFilter::new(filter::DoesMatch(EVENTID_SETTHREADCONTEXT));

    filter_open_thread.add_callback(syscall_detection_callback);
    filter_set_context_threat.add_callback(syscall_detection_callback);

    provider.add_filter(filter_open_thread);
    provider.add_filter(filter_set_context_threat);

    log::debug!(
        "Enabling provider {}: {}",
        provider.name,
        guid_to_string(&provider.guid)
    );

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
    unsafe { WaitForSingleObject(trace_thread_handle, 20000) };
    user_trace.stop();
}
