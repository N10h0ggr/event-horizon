use std::sync::Arc;
use crate::etw::types::{FilterCondition, EventCallback};
use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{TdhEnumerateProviders, EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_EVENT_ID, PROVIDER_ENUMERATION_INFO};
use crate::etw::errors::EtwError;
use crate::etw::manifest_parser::{EventSchema, ManifestParser};

/// ETW Log Levels (aligned with Windows definitions)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogLevel {
    Critical = 1,
    Error = 2,
    Warning = 3,
    Info = 4,
    Verbose = 5,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Verbose
    }
}

/// Represents a specific Event Filter configuration
#[derive(Clone)]
pub struct EventFilter {
    pub condition: FilterCondition,
    pub callbacks: Vec<Arc<EventCallback>>,
}

impl EventFilter {
    pub fn new(condition: FilterCondition) -> Self {
        Self {
            condition,
            callbacks: Vec::new(),
        }
    }

    pub fn add_callback(&mut self, callback: EventCallback) {
        self.callbacks.push(Arc::new(callback));
    }
}

/// Configuration for an ETW Provider
pub struct Provider {
    pub name: String,
    pub guid: GUID,
    pub any_keyword: u64,
    pub all_keyword: u64,
    pub level: LogLevel,
    pub trace_flags: Option<u32>,
    pub filters: Vec<EventFilter>,
    pub manifest: Option<ManifestParser>,
}

// Clone for Provider needs manual impl because ManifestParser is not strictly Clone
// (HashMap is cloneable, but conceptually ManifestParser is heavy)
impl Clone for Provider {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            guid: self.guid,
            any_keyword: self.any_keyword,
            all_keyword: self.all_keyword,
            level: self.level,
            trace_flags: self.trace_flags,
            filters: self.filters.clone(),
            // We usually don't want to clone the ManifestParser implicitly because it's heavy.
            // If the user wants it, they must re-load it or we need to make ManifestParser
            // internally ref-counted (Arc). For now, we set it to None on clone.
            manifest: None,
        }
    }
}

impl Provider {
    /// Creates a new Provider.
    pub fn new(guid: &str) -> Self {
        Self {
            name: Self::guid_to_name(guid),
            guid: crate::etw::utils::string_to_guid(guid),
            any_keyword: 0,
            all_keyword: 0,
            level: LogLevel::default(), // Defaults to Verbose
            trace_flags: None,
            filters: Vec::new(),
            manifest: None,
        }
    }

    /// Attempts to load and parse the ETW Manifest for this provider.
    /// This populates the `self.manifest` field.
    pub fn load_manifest(&mut self) -> crate::etw::errors::Result<()> {
        let parser = ManifestParser::new(self.guid)?;
        self.manifest = Some(parser);
        Ok(())
    }

    /// Builder: Set specific keywords
    pub fn keywords(mut self, any: u64, all: u64) -> Self {
        self.any_keyword = any;
        self.all_keyword = all;
        self
    }

    /// Builder: Set specific trace flags
    pub fn trace_flags(mut self, flags: u32) -> Self {
        self.trace_flags = Some(flags);
        self
    }
    
    /// Builder: Set log level
    pub fn level(mut self, level: LogLevel) -> Self {
        self.level = level;
        self
    }

    /// Add a filter to the provider
    pub fn add_filter(&mut self, filter: EventFilter) {
        self.filters.push(filter);
    }

    /// Internal helper to build the filter descriptors for EnableTraceEx2
    pub fn build_filter_descriptors(&self) -> (Vec<EVENT_FILTER_DESCRIPTOR>, Vec<Vec<u8>>) {
        let mut descriptors = Vec::new();
        let mut buffers = Vec::new();

        // Filter by Event ID
        // Note: Windows ETW filtering for Event IDs expects a specific binary layout:
        // EVENT_FILTER_EVENT_ID structure:
        // FilterIn (Boolean u8), Reserved (u8), Count (u16), EventIds (Array of u16)

        let event_ids: Vec<u16> = self.filters.iter()
            .filter_map(|f| {
                if let FilterCondition::DoesMatch(id) = f.condition {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();

        if !event_ids.is_empty() {
            let mut buffer = Vec::new();
            let filter_in: u8 = 1; // 1 = Include these IDs, 0 = Exclude
            let reserved: u8 = 0;
            let count: u16 = event_ids.len() as u16;

            buffer.extend_from_slice(&filter_in.to_ne_bytes());
            buffer.extend_from_slice(&reserved.to_ne_bytes());
            buffer.extend_from_slice(&count.to_ne_bytes());
            for id in event_ids {
                buffer.extend_from_slice(&id.to_ne_bytes());
            }

            let descriptor = EVENT_FILTER_DESCRIPTOR {
                Ptr: buffer.as_ptr() as u64,
                Size: buffer.len() as u32,
                Type: EVENT_FILTER_TYPE_EVENT_ID,
            };

            descriptors.push(descriptor);
            buffers.push(buffer); // Keep buffer alive so Ptr remains valid
        }

        (descriptors, buffers)
    }

    fn guid_to_name(guid_str: &str) -> String {
        let target_guid = crate::etw::utils::string_to_guid(guid_str);
        let mut buffer_size: u32 = 0;

        unsafe {
            // First call: Get the required buffer size
            let mut status = TdhEnumerateProviders(std::ptr::null_mut(), &mut buffer_size);

            // ERROR_INSUFFICIENT_BUFFER (122) is expected here
            if status != 122 && status != 0 {
                return guid_str.to_string();
            }

            // Allocate the buffer based on the returned size
            let mut buffer: Vec<u8> = vec![0u8; buffer_size as usize];
            let p_info = buffer.as_mut_ptr() as *mut PROVIDER_ENUMERATION_INFO;

            // Second call: Fill the buffer with actual provider data
            status = TdhEnumerateProviders(p_info, &mut buffer_size);

            if status == 0 {
                let info = &*p_info;
                // TraceProviderInfoArray is defined as [TRACE_PROVIDER_INFO; 1] in the bindings,
                // but it actually contains 'NumberOfProviders' elements in memory.
                let providers = std::slice::from_raw_parts(
                    info.TraceProviderInfoArray.as_ptr(),
                    info.NumberOfProviders as usize,
                );

                for provider in providers {
                    if crate::etw::utils::guids_equal(&provider.ProviderGuid, &target_guid) {
                        // The ProviderNameOffset is the byte offset from the start of the buffer
                        // to the null-terminated UTF-16 string (the provider name).
                        let name_ptr = (p_info as *const u8).offset(provider.ProviderNameOffset as isize) as *const u16;
                        return utf16_ptr_to_string(name_ptr);
                    }
                }
            }
        }

        guid_str.to_string()
    }
}

// --- Helper Functions ---

/// Safely converts a null-terminated PWSTR (UTF-16) to a Rust String
unsafe fn utf16_ptr_to_string(ptr: *const u16) -> String {
    unsafe {
        if ptr.is_null() { return String::new(); }
        let mut len = 0;
        while *ptr.offset(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len as usize);
        String::from_utf16_lossy(slice)
    }
}
