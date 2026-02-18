use crate::etw::provider::Provider;
use crate::etw::errors::{Result, EtwError};
use crate::etw::consumer;
use std::mem::{size_of, zeroed};
use std::sync::Arc;
// Import necessary Windows types directly as requested
use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, ERROR_ALREADY_EXISTS, GetLastError 
};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, EVENT_TRACE_PROPERTIES, StartTraceW, EnableTraceEx2, ControlTraceW,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_CONTROL_STOP,
    WNODE_FLAG_TRACED_GUID, ENABLE_TRACE_PARAMETERS,
    ENABLE_TRACE_PARAMETERS_VERSION_2
};

/// Represents the ETW Session Controller
pub struct UserTrace {
    session_name: String,
    // Handle to the trace session used for control (Start/Stop/Enable)
    // Type: CONTROLTRACE_HANDLE (u64)
    session_handle: CONTROLTRACE_HANDLE,
    // Stores active providers to keep their filters accessible to the consumer
    pub active_providers: Vec<Arc<Provider>>,
}

impl UserTrace {
    pub fn new(name: &str) -> Self {
        Self {
            session_name: name.to_string(),
            session_handle: CONTROLTRACE_HANDLE { Value: 0 },
            active_providers: Vec::new(),
        }
    }

    pub fn get_session_name(&self) -> String {
        self.session_name.clone()
    }

    /// Enables a provider for this session via EnableTraceEx2.
    pub fn enable(&mut self, provider: Provider) -> Result<()> {
        // Ensure the session is running
        if self.session_handle.Value == 0 {
            self.start_session()?;
        }

        // Prepare Enable Parameters (Used for Stack Tracing flags)
        let mut params: ENABLE_TRACE_PARAMETERS = unsafe { zeroed() };
        params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        
        // Map the provider flags (e.g., stack trace) to the EnableProperty
        if let Some(flags) = provider.trace_flags {
            params.EnableProperty = flags;
        }

        // Generate the descriptors and keep the backing buffers in scope
        let (descriptors, _buffers) = provider.build_filter_descriptors();
        if !descriptors.is_empty() {
            params.EnableFilterDesc = descriptors.as_ptr() as *mut _;
            params.FilterDescCount = descriptors.len() as u32;
        }

        // Enable the provider
        let result = unsafe {
            EnableTraceEx2(
                self.session_handle,
                &provider.guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                provider.level as u8,
                provider.any_keyword,
                provider.all_keyword,
                0,
                &params,
            )
        };

        if result != ERROR_SUCCESS {
            return Err(EtwError::WindowsError(result));
        }

        // Store the provider so the consumer can access its filters later
        // Store as a thread-safe shared reference
        self.active_providers.push(Arc::new(provider));
        
        Ok(())
    }

    /// Starts the blocking consumer loop.
    pub fn start(&self) -> u32 {
        if self.session_handle.Value == 0 {
            // Cannot consume a session that doesn't exist
            return 1; 
        }

        // Delegate to the consumer module to open the trace and process events
        // Pass 'self' so the consumer can access the 'active_providers' and 'session_name'
        log::debug!("Starting event consumer...");
        consumer::start_consumption(self)
    }

    /// Stops the ETW session.
    pub fn stop(&self) {
        log::debug!("Stopping ETW session...");
        if self.session_handle.Value == 0 {
            return;
        }

        // ETW writes the session name and log file name back into the buffer.
        // We must allocate extra space for these strings to avoid ERROR_MORE_DATA (234).
        let name_buffer_size = 1024 * std::mem::size_of::<u16>();
        let buf_size = (std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (name_buffer_size * 2)) as u32;

        let mut buffer = vec![0u8; buf_size as usize];
        let props = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        unsafe {
            let p = &mut *props;
            p.Wnode.BufferSize = buf_size;
            p.Wnode.Flags = WNODE_FLAG_TRACED_GUID; // Required for existing sessions

            // Define where ETW can write the names.
            // Offsets are relative to the start of the buffer.
            p.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            p.LogFileNameOffset = (std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_buffer_size) as u32;

            let status = ControlTraceW(
                self.session_handle,
                std::ptr::null(),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );

            if status != ERROR_SUCCESS {
                log::error!("Error stopping ETW session: {}", status);
            } else {
                log::debug!("ETW session stopped successfully.");
            }
        }
    }

    /// Private helper to start the trace session via StartTraceW
    fn start_session(&mut self) -> Result<()> {
        // Encode session name to UTF-16
        let session_name_wide: Vec<u16> = self.session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        
        let session_name_bytes = session_name_wide.len() * size_of::<u16>();

        // Calculate total buffer size: Struct + Session Name
        // NOTE: EVENT_TRACE_PROPERTIES must be contiguous with the name
        let struct_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let name_bytes = session_name_wide.len() * size_of::<u16>();
        let total_size = struct_size + name_bytes;

        // Allocate buffer
        // Here we use u64 to correctly align the buffer to the
        // the 8-byte alignment and memory layout described in MSDN
        // ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties#remarks
        let num_u64s = (total_size + 7) / 8;
        let mut buffer = vec![0u64; num_u64s];

        // Get pointer to the struct part
        let props_ptr = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        unsafe {

            // Initialize WNODE_HEADER
            (*props_ptr).Wnode.BufferSize = total_size as u32;
            (*props_ptr).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props_ptr).Wnode.ClientContext = 1; // 1 = QPC (High resolution clock)


            // For User-mode sessions, a unique GUID allows EnableTraceEx2 to target this session reliably.
            // For Kernel-mode sessions we need to set this member to SystemTraceControlGuid.
            // ref: https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header#members
            let session_guid = uuid::Uuid::new_v4();
            let (d1, d2, d3, d4) = session_guid.to_fields_le();
            (*props_ptr).Wnode.Guid = windows_sys::core::GUID {
                data1: d1,
                data2: d2,
                data3: d3,
                data4: *d4,
            };

            // Initialize Properties
            (*props_ptr).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props_ptr).BufferSize = 64;
            (*props_ptr).MinimumBuffers = 2;
            (*props_ptr).MaximumBuffers = 20;
            (*props_ptr).FlushTimer = 1;      // Flush every 1 second

            // Set offsets.
            // LoggerNameOffset is the byte offset from the start of the struct to the name
            (*props_ptr).LoggerNameOffset = struct_size as u32;
            (*props_ptr).LogFileNameOffset = 0; // 0 because we are RealTime (no file)

            // Copy the name into the buffer after the struct
            let name_dest = buffer.as_mut_ptr().add(struct_size) as *mut u16;
            std::ptr::copy_nonoverlapping(
                session_name_wide.as_ptr(), 
                name_dest, 
                session_name_wide.len()
            );

            // Call StartTraceW
            let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
            let result = StartTraceW(
                &mut handle,
                session_name_wide.as_ptr(),
                props_ptr,
            );

            match result {
                ERROR_SUCCESS => {
                    self.session_handle = handle;
                    Ok(())
                },
                ERROR_ALREADY_EXISTS => {
                    // Session exists. We must attach to it. 
                    // However, StartTraceW doesn't return the handle if it exists.
                    // We must use ControlTraceW with EVENT_TRACE_CONTROL_QUERY to get the handle 
                    // or simply stop it and restart. For simplicity, we usually want to own the
                    // session, so we might stop and restart, or just fail.
                    
                    // Attempt to stop the existing one (blindly) and retry
                    log::warn!("ETW session already exists. Stopping and retrying...");
                    ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, session_name_wide.as_ptr(), props_ptr, EVENT_TRACE_CONTROL_STOP);

                    // Retry Start
                    let retry_result = StartTraceW(&mut handle, session_name_wide.as_ptr(), props_ptr);
                    if retry_result == ERROR_SUCCESS {
                        self.session_handle = handle;
                        Ok(())
                    } else {
                        Err(EtwError::SessionAlreadyExists)
                    }
                },
                err => Err(EtwError::WindowsError(err))
            }
        }
    }
}