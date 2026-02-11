use crate::schema::{EtwInType, EtwManifest};
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::collections::HashMap;
use windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD;

pub fn parse_event(record: &EVENT_RECORD, schema: &EtwManifest) -> Result<Value> {
    // ... (This function remains largely the same, calling parse_field) ...
    let descriptor = record.EventHeader.EventDescriptor;
    let event_id = descriptor.Id;
    let version = descriptor.Version;

    let event_schema = schema
        .events
        .iter()
        .find(|e| e.event_id == event_id && e.version == version);

    if let Some(event) = event_schema {
        let mut json_fields = HashMap::new();
        let user_data = record.UserData as *const u8;
        let user_data_len = record.UserDataLength as usize;
        let mut offset = 0;

        for field in &event.fields {
            if offset >= user_data_len {
                break;
            }
            // Safety: parse_field handles bounds checking via read_type
            let (value, size) = unsafe {
                parse_field(
                    user_data,
                    offset,
                    user_data_len,
                    &field.in_type,
                    &record.EventHeader,
                )?
            };
            json_fields.insert(field.name.clone(), value);
            offset += size;
        }

        // Standard Metadata
        json_fields.insert("event_id".to_string(), json!(event_id));
        json_fields.insert("version".to_string(), json!(version));
        json_fields.insert("opcode".to_string(), json!(descriptor.Opcode));
        json_fields.insert("level".to_string(), json!(descriptor.Level));
        json_fields.insert("task".to_string(), json!(descriptor.Task));
        json_fields.insert("keyword".to_string(), json!(descriptor.Keyword));
        json_fields.insert(
            "provider_guid".to_string(),
            json!(schema.provider_guid.to_string()),
        );
        json_fields.insert("provider_name".to_string(), json!(schema.provider_name));

        let event_name_version = format!("{}_{}", event.event_name, version);
        json_fields.insert("event_name_version".to_string(), json!(event_name_version));

        // Timestamp
        let windows_ticks = record.EventHeader.TimeStamp;
        const WINDOWS_EPOCH_OFFSET_TICKS: i64 = 11_644_473_600 * 10_000_000;
        let unix_micros = (windows_ticks - WINDOWS_EPOCH_OFFSET_TICKS) / 10;
        let unix_millis = unix_micros / 1000;
        json_fields.insert("timestamp".to_string(), json!(unix_millis));

        Ok(json!(json_fields))
    } else {
        Ok(json!({
            "event_id": event_id,
            "error": "Unknown event schema"
        }))
    }
}

// Helper to read primitive types safely
unsafe fn read_type<T: Copy>(ptr: *const u8, offset: usize, max_len: usize) -> Result<T> {
    if offset + std::mem::size_of::<T>() > max_len {
        return Err(anyhow!("Buffer overflow reading type"));
    }
    unsafe { Ok(ptr.add(offset).cast::<T>().read_unaligned()) }
}

unsafe fn parse_field(
    base_ptr: *const u8,
    offset: usize,
    max_len: usize,
    in_type: &EtwInType,
    header: &windows_sys::Win32::System::Diagnostics::Etw::EVENT_HEADER,
) -> Result<(Value, usize)> {
    let ptr = unsafe { base_ptr.add(offset) };

    match in_type {
        // Standard Integers (Keep as Numbers)
        EtwInType::Int8 => Ok((
            json!(unsafe { read_type::<i8>(base_ptr, offset, max_len)? }),
            1,
        )),
        EtwInType::Uint8 => Ok((
            json!(unsafe { read_type::<u8>(base_ptr, offset, max_len)? }),
            1,
        )),
        EtwInType::Int16 => Ok((
            json!(unsafe { read_type::<i16>(base_ptr, offset, max_len)? }),
            2,
        )),
        EtwInType::Uint16 => Ok((
            json!(unsafe { read_type::<u16>(base_ptr, offset, max_len)? }),
            2,
        )),
        EtwInType::Int32 => Ok((
            json!(unsafe { read_type::<i32>(base_ptr, offset, max_len)? }),
            4,
        )),
        EtwInType::Uint32 => Ok((
            json!(unsafe { read_type::<u32>(base_ptr, offset, max_len)? }),
            4,
        )),
        EtwInType::Int64 => Ok((
            json!(unsafe { read_type::<i64>(base_ptr, offset, max_len)? }),
            8,
        )),
        EtwInType::Uint64 => Ok((
            json!(unsafe { read_type::<u64>(base_ptr, offset, max_len)? }),
            8,
        )),

        // Hexadecimal Types -> Convert to Hex String "0x..."
        EtwInType::HexInt32 => {
            let val = unsafe { read_type::<u32>(base_ptr, offset, max_len)? };
            Ok((json!(format!("0x{:x}", val)), 4))
        }
        EtwInType::HexInt64 => {
            let val = unsafe { read_type::<u64>(base_ptr, offset, max_len)? };
            Ok((json!(format!("0x{:x}", val)), 8))
        }
        EtwInType::Pointer => {
            let is_64bit = (header.Flags & 0x40) != 0;
            let is_32bit = (header.Flags & 0x20) != 0;
            let pointer_size = if is_64bit {
                8
            } else if is_32bit {
                4
            } else {
                std::mem::size_of::<usize>()
            };

            if pointer_size == 8 {
                let val = unsafe { read_type::<u64>(base_ptr, offset, max_len)? };
                Ok((json!(format!("0x{:x}", val)), 8))
            } else {
                let val = unsafe { read_type::<u32>(base_ptr, offset, max_len)? };
                Ok((json!(format!("0x{:x}", val)), 4))
            }
        }

        EtwInType::Float => Ok((
            json!(unsafe { read_type::<f32>(base_ptr, offset, max_len)? }),
            4,
        )),
        EtwInType::Double => Ok((
            json!(unsafe { read_type::<f64>(base_ptr, offset, max_len)? }),
            8,
        )),
        EtwInType::Boolean => {
            let val = unsafe { read_type::<u32>(base_ptr, offset, max_len)? };
            Ok((json!(val != 0), 4))
        }
        EtwInType::Guid => {
            let guid = unsafe { read_type::<windows_sys::core::GUID>(base_ptr, offset, max_len)? };
            let s = format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                guid.data1,
                guid.data2,
                guid.data3,
                guid.data4[0],
                guid.data4[1],
                guid.data4[2],
                guid.data4[3],
                guid.data4[4],
                guid.data4[5],
                guid.data4[6],
                guid.data4[7]
            );
            Ok((json!(s), 16))
        }
        EtwInType::UnicodeString => {
            let mut len_bytes = 0;
            let mut str_bytes = Vec::new();
            loop {
                if offset + len_bytes + 2 > max_len {
                    break;
                }
                let c = unsafe { (ptr.add(len_bytes) as *const u16).read_unaligned() };
                len_bytes += 2;
                if c == 0 {
                    break;
                }
                str_bytes.push(c);
            }
            Ok((json!(String::from_utf16_lossy(&str_bytes)), len_bytes))
        }
        EtwInType::AnsiString => {
            let mut len_bytes = 0;
            let mut str_bytes = Vec::new();
            loop {
                if offset + len_bytes + 1 > max_len {
                    break;
                }
                let c = unsafe { ptr.add(len_bytes).read() };
                len_bytes += 1;
                if c == 0 {
                    break;
                }
                str_bytes.push(c);
            }
            Ok((json!(String::from_utf8_lossy(&str_bytes)), len_bytes))
        }
        EtwInType::FileTime => {
            // FileTime is usually best kept as u64 or converted to Date, but u64 is standard raw
            Ok((
                json!(unsafe { read_type::<u64>(base_ptr, offset, max_len)? }),
                8,
            ))
        }
        EtwInType::SystemTime => {
            let st = unsafe {
                read_type::<windows_sys::Win32::Foundation::SYSTEMTIME>(base_ptr, offset, max_len)?
            };
            let s = format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
            );
            Ok((json!(s), 16))
        }
        EtwInType::Sid => {
            if offset + 8 > max_len {
                return Err(anyhow!("Overflow"));
            }
            let sub_auth_count = unsafe { *ptr.add(1) } as usize;
            let size = 8 + (sub_auth_count * 4);
            if offset + size > max_len {
                return Err(anyhow!("Overflow"));
            }
            Ok((json!("SID"), size))
        }
        _ => Err(anyhow!("Unsupported ETW InType: {:?}", in_type)),
    }
}
