use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwManifest {
    pub provider_guid: Uuid,
    pub provider_name: String,
    pub events: Vec<EtwEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwEvent {
    pub event_id: u16,
    pub version: u8,
    pub opcode: u8,
    pub level: u8,
    pub task: u16,
    pub keyword: u64,
    pub event_name: String, // Renamed from task_name to reflect resolved logic
    pub fields: Vec<EtwField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwField {
    pub name: String,
    pub in_type: EtwInType,
    pub out_type: EtwOutType,
}

// ... (Enums EtwInType and EtwOutType remain unchanged) ...
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u16)]
pub enum EtwInType {
    Null = 0,
    UnicodeString = 1,
    AnsiString = 2,
    Int8 = 3,
    Uint8 = 4,
    Int16 = 5,
    Uint16 = 6,
    Int32 = 7,
    Uint32 = 8,
    Int64 = 9,
    Uint64 = 10,
    Float = 11,
    Double = 12,
    Boolean = 13,
    Binary = 14,
    Guid = 15,
    Pointer = 16,
    FileTime = 17,
    SystemTime = 18,
    Sid = 19,
    HexInt32 = 20,
    HexInt64 = 21,
    CountedString = 22,
    CountedAnsiString = 23,
    Struct = 24,
    CountedBinary = 25,
    Unknown = 0xFFFF,
}

impl From<u16> for EtwInType {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Null,
            1 => Self::UnicodeString,
            2 => Self::AnsiString,
            3 => Self::Int8,
            4 => Self::Uint8,
            5 => Self::Int16,
            6 => Self::Uint16,
            7 => Self::Int32,
            8 => Self::Uint32,
            9 => Self::Int64,
            10 => Self::Uint64,
            11 => Self::Float,
            12 => Self::Double,
            13 => Self::Boolean,
            14 => Self::Binary,
            15 => Self::Guid,
            16 => Self::Pointer,
            17 => Self::FileTime,
            18 => Self::SystemTime,
            19 => Self::Sid,
            20 => Self::HexInt32,
            21 => Self::HexInt64,
            22 => Self::CountedString,
            23 => Self::CountedAnsiString,
            24 => Self::Struct,
            25 => Self::CountedBinary,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u16)]
pub enum EtwOutType {
    Null = 0,
    String = 1,
    DateTime = 2,
    Byte = 3,
    UnsignedByte = 4,
    Short = 5,
    UnsignedShort = 6,
    Int = 7,
    UnsignedInt = 8,
    Long = 9,
    UnsignedLong = 10,
    Float = 11,
    Double = 12,
    Boolean = 13,
    Guid = 14,
    HexBinary = 15,
    HexInt8 = 16,
    HexInt16 = 17,
    HexInt32 = 18,
    HexInt64 = 19,
    Pid = 20,
    Tid = 21,
    Port = 22,
    Ipv4 = 23,
    Ipv6 = 24,
    SocketAddress = 25,
    CimDateTime = 26,
    EtwTime = 27,
    Xml = 28,
    ErrorCode = 29,
    Win32Error = 30,
    NtStatus = 31,
    HResult = 32,
    CultureInsensitiveDateTime = 33,
    Json = 34,
    Utf8 = 35,
    Pkcs7WithTypeInfo = 36,
    CodePointer = 37,
    UtcDateTime = 38,
    ReducedString = 39,
    NoPrint = 40,
    Unknown = 0xFFFF,
}

impl From<u16> for EtwOutType {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Null,
            1 => Self::String,
            2 => Self::DateTime,
            3 => Self::Byte,
            4 => Self::UnsignedByte,
            5 => Self::Short,
            6 => Self::UnsignedShort,
            7 => Self::Int,
            8 => Self::UnsignedInt,
            9 => Self::Long,
            10 => Self::UnsignedLong,
            11 => Self::Float,
            12 => Self::Double,
            13 => Self::Boolean,
            14 => Self::Guid,
            15 => Self::HexBinary,
            16 => Self::HexInt8,
            17 => Self::HexInt16,
            18 => Self::HexInt32,
            19 => Self::HexInt64,
            20 => Self::Pid,
            21 => Self::Tid,
            22 => Self::Port,
            23 => Self::Ipv4,
            24 => Self::Ipv6,
            25 => Self::SocketAddress,
            26 => Self::CimDateTime,
            27 => Self::EtwTime,
            28 => Self::Xml,
            29 => Self::ErrorCode,
            30 => Self::Win32Error,
            31 => Self::NtStatus,
            32 => Self::HResult,
            33 => Self::CultureInsensitiveDateTime,
            34 => Self::Json,
            35 => Self::Utf8,
            36 => Self::Pkcs7WithTypeInfo,
            37 => Self::CodePointer,
            38 => Self::UtcDateTime,
            39 => Self::ReducedString,
            40 => Self::NoPrint,
            _ => Self::Unknown,
        }
    }
}
