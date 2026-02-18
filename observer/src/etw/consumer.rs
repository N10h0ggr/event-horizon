use crate::etw::controller::UserTrace;
use crate::etw::types::{Event, FilterCondition};
use std::ffi::c_void;
use std::ptr::{null};
use std::mem::zeroed;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, FILETIME};
use windows_sys::Win32::System::Diagnostics::Etw::*;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::core::GUID;

// Constants for ProcessTraceMode
// PROCESS_TRACE_MODE_EVENT_RECORD (0x10000000) | PROCESS_TRACE_MODE_REAL_TIME (0x00000100)
const REAL_TIME_EVENT_RECORD_MODE: u32 = 0x10000100; 
const INVALID_PROCESSTRACE_HANDLE_VAL: u64 = 0xFFFFFFFFFFFFFFFF;

fn is_same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 
        && a.data2 == b.data2 
        && a.data3 == b.data3 
        && a.data4 == b.data4
}

/// The global static callback required by the Windows C API.
/// 
/// # Safety
/// This function is called by the OS. It receives a raw pointer to an EVENT_RECORD.
/// It relies on the `UserContext` field of the record being a valid pointer to our `UserTrace` struct.
unsafe extern "system" fn global_etw_callback(record: *mut EVENT_RECORD) {
    
    if record.is_null() {
        log::error!("EventRecord is null!");
        return;
    }

    // Retrieve the Context
    // When we called OpenTrace, we set the Context field to point to our UserTrace instance.
    // Windows passes this back in the UserContext field of the EVENT_RECORD.
    let context_ptr = unsafe { (*record).UserContext };
    if context_ptr.is_null() {
        log::error!("EventRecord.UserContext is null!");
        return; // Should not happen if initialized correctly
    }

    // Cast back to Rust reference
    // Safety: We must ensure UserTrace lives as long as the trace session (handled in main.rs)
    let user_trace = unsafe { &*(context_ptr as *const UserTrace) };

    // Wrap the raw record in our safe 'Event' type
    let event = unsafe { Event::new(record as *const c_void) };
    let event_guid = event.provider_guid();

    // Filter and Dispatch
    // We iterate over all providers active in this session
    for provider in &user_trace.active_providers {
        
        // Note: Might need to add a comparison method or check GUIDs here.
        if !is_same_guid(&provider.guid, &event_guid) { 
            continue; 
        }

        for filter in &provider.filters {
            let should_fire = match filter.condition {
                FilterCondition::DoesMatch(id) => event.id() == id,
                FilterCondition::DoesNotMatch(id) => event.id() != id,
            };

            if should_fire {
                for callback in &filter.callbacks {
                    (callback)(&event);
                }
            }
        }
    }
}

/// Starts the blocking consumption loop.
/// 
/// This function:
/// 1. Configures the EVENT_TRACE_LOGFILE structure.
/// 2. Opens the trace session.
/// 3. Enters the blocking ProcessTrace loop.
pub fn start_consumption(trace: &UserTrace) -> u32 {
    unsafe {
        // We must keep this allocation alive until OpenTraceW is called.
        let mut session_name_wide: Vec<u16> = trace.get_session_name() 
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut log_file: EVENT_TRACE_LOGFILEW = zeroed();
        
        // Set the name of the session we want to consume
        log_file.LoggerName = session_name_wide.as_mut_ptr();
        
        // Set the mode to Real-Time + Event Record format (newer, better format)
        // We access the anonymous union via the generated field name (check windows-sys binding specific, usually Anonymous1)
        log_file.Anonymous1.ProcessTraceMode = REAL_TIME_EVENT_RECORD_MODE;

        // Set the callback strategy
        // We use the 'EventRecordCallback' field in the Anonymous2 union
        log_file.Anonymous2.EventRecordCallback = Some(global_etw_callback);

        // CRITICAL: Pass the UserTrace reference as the Context.
        // This allows the static callback to access our Rust data structures.
        log_file.Context = trace as *const UserTrace as *mut c_void;

        // This returns a PROCESSTRACE_HANDLE (which is just a u64)
        let trace_handle =  OpenTraceW(&mut log_file);

        if trace_handle.Value == INVALID_PROCESSTRACE_HANDLE_VAL {
            return GetLastError();
        }

        // Process the Trace (Blocking)
        // This function blocks the current thread until the session is stopped externally
        // or the buffer callback returns FALSE (not used here).
        log::debug!("Starting ProcessTrace");
        let result = ProcessTrace(
            &trace_handle, // Array of handles
            1,             // Count
            null(),        // Start time (optional)
            null()         // End time (optional)
        );
        if result != ERROR_SUCCESS {
            log::error!("ProcessTrace failed with error {}", result);
            return GetLastError();
        } else {
            log::debug!("Closing trace session");
            CloseTrace(trace_handle);
        }

        result
    }
}