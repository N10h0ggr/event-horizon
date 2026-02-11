use crate::schema::{EtwEvent, EtwField, EtwInType, EtwManifest, EtwOutType};
use anyhow::{Result, anyhow};
use log::{debug, warn};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_DESCRIPTOR, PROVIDER_EVENT_INFO, PropertyStruct, TRACE_EVENT_INFO,
    TdhEnumerateManifestProviderEvents, TdhGetManifestEventInformation,
};

pub fn fetch_manifest_for_provider(provider_guid: uuid::Uuid) -> Result<EtwManifest> {
    let guid = to_win_guid(&provider_guid);

    debug!("Fetching manifest for provider: {:?}", provider_guid);

    // 1. Get the list of Event Descriptors
    let provider_info_buffer = get_provider_events_buffer(&guid)?;
    let provider_info = unsafe { &*(provider_info_buffer.as_ptr() as *const PROVIDER_EVENT_INFO) };

    let mut events = Vec::new();
    let mut resolved_provider_name = String::new();

    let descriptors_ptr = provider_info.EventDescriptorsArray.as_ptr();
    let count = provider_info.NumberOfEvents;

    for i in 0..count {
        let descriptor = unsafe { &*descriptors_ptr.add(i as usize) };

        match get_event_info_buffer(&guid, descriptor) {
            Ok(event_info_buffer) => {
                // Pass the buffer to the parser
                match parse_trace_event_info(descriptor, &event_info_buffer) {
                    Ok((event_schema, p_name)) => {
                        // Capture provider name if we haven't found one yet
                        if resolved_provider_name.is_empty() && !p_name.is_empty() {
                            resolved_provider_name = p_name;
                        }
                        events.push(event_schema);
                    }
                    Err(e) => {
                        warn!("Failed to parse info for event ID {}: {}", descriptor.Id, e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to get info for event ID {}: {}", descriptor.Id, e);
            }
        }
    }

    // Fallback if name is still missing (use GUID)
    if resolved_provider_name.is_empty() {
        resolved_provider_name = provider_guid.to_string();
    }

    Ok(EtwManifest {
        provider_guid,
        provider_name: resolved_provider_name,
        events,
    })
}

// --- Helpers ---

/// Returns the Event Schema AND the Provider Name found in this specific event info
fn parse_trace_event_info(
    descriptor: &EVENT_DESCRIPTOR,
    buffer: &[u8],
) -> Result<(EtwEvent, String)> {
    let info = unsafe { &*(buffer.as_ptr() as *const TRACE_EVENT_INFO) };
    let mut fields = Vec::new();

    let properties_ptr = info.EventPropertyInfoArray.as_ptr();

    for i in 0..info.TopLevelPropertyCount {
        let prop = unsafe { &*properties_ptr.add(i as usize) };
        let name = unsafe { read_str_at_offset(buffer.as_ptr(), prop.NameOffset as usize) };

        let (in_type, out_type) = if (prop.Flags & PropertyStruct) == 0 {
            unsafe {
                (
                    prop.Anonymous1.nonStructType.InType,
                    prop.Anonymous1.nonStructType.OutType,
                )
            }
        } else {
            (0, 0)
        };

        fields.push(EtwField {
            name,
            in_type: EtwInType::from(in_type),
            out_type: EtwOutType::from(out_type),
        });
    }

    // --- Provider Name Extraction (Per User Corrected Logic) ---
    // The offset is relative to the start of the TRACE_EVENT_INFO buffer
    let provider_name =
        unsafe { read_str_at_offset(buffer.as_ptr(), info.ProviderNameOffset as usize) };

    // --- Event Name Resolution (Task -> Opcode -> ID) ---
    let task_name = unsafe { read_str_at_offset(buffer.as_ptr(), info.TaskNameOffset as usize) };
    let opcode_name =
        unsafe { read_str_at_offset(buffer.as_ptr(), info.OpcodeNameOffset as usize) };

    let event_name = if !task_name.is_empty() {
        task_name
    } else if !opcode_name.is_empty() {
        opcode_name
    } else {
        format!("Event_{}", descriptor.Id)
    };

    Ok((
        EtwEvent {
            event_id: descriptor.Id,
            version: descriptor.Version,
            opcode: descriptor.Opcode,
            level: descriptor.Level,
            task: descriptor.Task,
            keyword: descriptor.Keyword,
            event_name, // Populated with the fallback logic
            fields,
        },
        provider_name,
    ))
}

fn get_provider_events_buffer(guid: &windows_sys::core::GUID) -> Result<Vec<u8>> {
    let mut buffer_size = 0;
    let status =
        unsafe { TdhEnumerateManifestProviderEvents(guid, ptr::null_mut(), &mut buffer_size) };

    if status != ERROR_INSUFFICIENT_BUFFER {
        if status == windows_sys::Win32::Foundation::ERROR_NOT_FOUND {
            return Err(anyhow!(
                "Provider manifest not found. Is the provider registered?"
            ));
        }
        return Err(anyhow!(
            "Failed to get provider events size: Win32 error {}",
            status
        ));
    }

    let mut buffer = vec![0u8; buffer_size as usize];
    let status = unsafe {
        TdhEnumerateManifestProviderEvents(guid, buffer.as_mut_ptr() as *mut _, &mut buffer_size)
    };

    if status != ERROR_SUCCESS {
        return Err(anyhow!(
            "TdhEnumerateManifestProviderEvents failed: Win32 error {}",
            status
        ));
    }

    Ok(buffer)
}

fn get_event_info_buffer(
    guid: &windows_sys::core::GUID,
    desc: &EVENT_DESCRIPTOR,
) -> Result<Vec<u8>> {
    let mut buffer_size = 0;
    let status =
        unsafe { TdhGetManifestEventInformation(guid, desc, ptr::null_mut(), &mut buffer_size) };

    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(anyhow!(
            "Failed to get event info size: Win32 error {}",
            status
        ));
    }

    let mut buffer = vec![0u8; buffer_size as usize];
    let status = unsafe {
        TdhGetManifestEventInformation(guid, desc, buffer.as_mut_ptr() as *mut _, &mut buffer_size)
    };

    if status != ERROR_SUCCESS {
        return Err(anyhow!(
            "TdhGetManifestEventInformation failed: Win32 error {}",
            status
        ));
    }

    Ok(buffer)
}

unsafe fn read_str_at_offset(base_ptr: *const u8, offset: usize) -> String {
    if offset == 0 {
        return String::new();
    }
    unsafe {
        let mut ptr = base_ptr.add(offset);
        let mut buf = Vec::new();
        loop {
            let c = (ptr as *const u16).read_unaligned();
            if c == 0 {
                break;
            }
            buf.push(c);
            ptr = ptr.add(2);
        }
        String::from_utf16_lossy(&buf).trim().to_string()
    }
}

pub fn to_win_guid(uuid: &uuid::Uuid) -> windows_sys::core::GUID {
    let (d1, d2, d3, d4) = uuid.as_fields();
    windows_sys::core::GUID {
        data1: d1,
        data2: d2,
        data3: d3,
        data4: *d4,
    }
}
