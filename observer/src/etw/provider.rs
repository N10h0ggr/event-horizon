use crate::etw::parser;
use crate::schema::EtwManifest;
use anyhow::{Result, anyhow};
use log::{error, info, warn};
use serde_json::Value;
use std::ptr;
use std::sync::mpsc::Sender;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace, StartTraceW, WNODE_FLAG_TRACED_GUID,
};

/// Context passed to the callback function.
struct EtwContext {
    schema: EtwManifest,
    sender: Sender<Value>,
}

pub fn start_trace_session(
    session_name: &str,
    provider_guid: &windows_sys::core::GUID,
) -> Result<u64> {
    let session_name_wide: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Size: Struct + Name + buffer
    let buffer_size =
        std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (session_name_wide.len() * 2) + 2048;
    let mut buffer = vec![0u8; buffer_size];

    let props = unsafe { &mut *(buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };

    props.Wnode.BufferSize = buffer_size as u32;
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.Wnode.ClientContext = 1; // QPC
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

    let session_handle: u64 = 0;

    // Best effort stop
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            session_name_wide.as_ptr(),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
    }

    // Reset properties
    props.Wnode.BufferSize = buffer_size as u32;
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.Wnode.ClientContext = 1;
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

    info!("Starting ETW session '{}'...", session_name);

    let mut control_handle = CONTROLTRACE_HANDLE {
        Value: session_handle,
    };

    let status = unsafe { StartTraceW(&mut control_handle, session_name_wide.as_ptr(), props) };

    if status != ERROR_SUCCESS {
        return Err(anyhow!("StartTraceW failed with error {}", status));
    }

    info!("ETW Session started. Handle: {:x}", control_handle.Value);

    let status = unsafe {
        EnableTraceEx2(
            control_handle,
            provider_guid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            4,                     // Verbose/Info
            0xFFFFFFFFFFFFFFFFu64, // All Keywords
            0,
            0,
            ptr::null_mut(),
        )
    };

    if status != ERROR_SUCCESS {
        stop_trace_session(session_name);
        return Err(anyhow!("EnableTraceEx2 failed with error {}", status));
    }

    info!("Provider enabled.");
    Ok(session_handle)
}

pub fn stop_trace_session(session_name: &str) {
    let session_name_wide: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let buffer_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 4096;
    let mut buffer = vec![0u8; buffer_size];
    let props = unsafe { &mut *(buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
    props.Wnode.BufferSize = buffer_size as u32;

    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            session_name_wide.as_ptr(),
            props,
            EVENT_TRACE_CONTROL_STOP,
        )
    };

    if status != ERROR_SUCCESS {
        warn!("ControlTraceW (STOP) returned {}", status);
    } else {
        info!("ETW Session stopped.");
    }
}

/// The safe C-callback wrapper
unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }

    let record_ref = unsafe { &*record };

    // Safety: UserContext is void*, we cast it back to our Rust struct.
    // This pointer is guaranteed valid because we box/leak it in process_events
    // and only free it after ProcessTrace returns.
    if record_ref.UserContext.is_null() {
        return;
    }

    let ctx = unsafe { &*(record_ref.UserContext as *const EtwContext) };

    match parser::parse_event(record_ref, &ctx.schema) {
        Ok(json) => {
            if let Err(e) = ctx.sender.send(json) {
                error!("Failed to send event to channel: {}", e);
            }
        }
        Err(_e) => {
            // Only log occasional errors or debug to avoid flooding
            // warn!("Failed to parse: {}", e);
        }
    }
}

pub fn process_events(
    session_name: &str,
    schema: EtwManifest,
    sender: Sender<Value>,
) -> Result<()> {
    // We Box the context and leak it into a raw pointer.
    // This pointer remains valid for the duration of ProcessTrace.
    let context = Box::new(EtwContext { schema, sender });
    let context_ptr = Box::into_raw(context);

    let session_name_wide: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut log_file: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    log_file.LoggerName = session_name_wide.as_ptr() as *mut u16;
    log_file.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

    // Set the callback
    log_file.Anonymous2.EventRecordCallback = Some(event_record_callback);

    // Set the context! ETW will pass this back in EVENT_RECORD.UserContext
    log_file.Context = context_ptr as *mut _;

    info!("Opening trace for processing...");
    let trace_handle = unsafe { OpenTraceW(&mut log_file as *mut EVENT_TRACE_LOGFILEW) };

    if trace_handle.Value == INVALID_HANDLE_VALUE as u64 {
        // Reclaim memory before returning error
        unsafe {
            let _ = Box::from_raw(context_ptr);
        }
        return Err(anyhow!("OpenTraceW failed."));
    }

    info!("Processing traces... (blocking)");
    let status = unsafe {
        ProcessTrace(
            &trace_handle as *const _,
            1,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };

    // Clean up
    unsafe { CloseTrace(trace_handle) };

    // Reclaim memory (Drop the Box)
    unsafe {
        let _ = Box::from_raw(context_ptr);
    }

    if status != ERROR_SUCCESS {
        return Err(anyhow!("ProcessTrace failed with status {}", status));
    }

    Ok(())
}
