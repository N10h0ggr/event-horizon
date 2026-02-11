use crate::schema::{EtwField, EtwManifest};
use serde_json::{Value, json};
use std::collections::HashMap;

pub fn generate_index_mapping(manifest: &EtwManifest) -> Value {
    let mut properties = HashMap::new();

    properties.insert("event_id", json!({ "type": "integer" }));
    properties.insert("provider_guid", json!({ "type": "keyword" }));
    properties.insert("provider_name", json!({ "type": "keyword" })); // Added
    properties.insert("event_name_version", json!({ "type": "keyword" })); // Added
    properties.insert("version", json!({ "type": "integer" }));
    properties.insert("opcode", json!({ "type": "integer" }));
    properties.insert("level", json!({ "type": "integer" }));
    properties.insert("task", json!({ "type": "integer" }));
    properties.insert("keyword", json!({ "type": "keyword" }));
    properties.insert("timestamp", json!({ "type": "date" }));

    for event in &manifest.events {
        for field in &event.fields {
            let field_mapping = map_etw_type_to_elastic(field);
            properties.insert(field.name.as_str(), field_mapping);
        }
    }

    json!({
        "mappings": {
            "properties": properties
        }
    })
}

// ... (map_etw_type_to_elastic remains unchanged from previous suggestion) ...
fn map_etw_type_to_elastic(_field: &EtwField) -> Value {
    // match field.in_type {
    //     EtwInType::UnicodeString
    //     | EtwInType::AnsiString
    //     | EtwInType::CountedString
    //     | EtwInType::CountedAnsiString => {
    //         json!({
    //             "type": "text",
    //             "fields": {
    //                 "keyword": {
    //                     "type": "keyword",
    //                     "ignore_above": 256
    //                 }
    //             }
    //         })
    //     }
    //     EtwInType::Int8
    //     | EtwInType::Uint8
    //     | EtwInType::Int16
    //     | EtwInType::Uint16
    //     | EtwInType::Int32 => {
    //         json!({ "type": "integer" })
    //     }
    //     EtwInType::Uint32 | EtwInType::HexInt32 | EtwInType::Int64 => json!({ "type": "long" }),
    //     EtwInType::Uint64 | EtwInType::HexInt64 | EtwInType::Pointer | EtwInType::FileTime => {
    //         use crate::schema::{EtwField, EtwInType, EtwManifest};
    //         use serde_json::{Value, json};
    //         use std::collections::HashMap;

    //         pub fn generate_index_mapping(manifest: &EtwManifest) -> Value {
    //             let mut properties = HashMap::new();

    //             // Standard fields
    //             properties.insert("event_id", json!({ "type": "integer" }));
    //             properties.insert("provider_guid", json!({ "type": "keyword" }));
    //             properties.insert("provider_name", json!({ "type": "keyword" }));
    //             properties.insert("event_name_version", json!({ "type": "keyword" }));
    //             properties.insert("version", json!({ "type": "integer" }));
    //             properties.insert("opcode", json!({ "type": "integer" }));
    //             properties.insert("level", json!({ "type": "integer" }));
    //             properties.insert("task", json!({ "type": "integer" }));
    //             properties.insert("keyword", json!({ "type": "unsigned_long" }));
    //             properties.insert("timestamp", json!({ "type": "date" }));

    //             for event in &manifest.events {
    //                 for field in &event.fields {
    //                     let field_mapping = map_etw_type_to_elastic(field);
    //                     properties.insert(field.name.as_str(), field_mapping);
    //                 }
    //             }

    //             json!({
    //                 "mappings": {
    //                     "properties": properties
    //                 }
    //             })
    //         }

    //         fn map_etw_type_to_elastic(field: &EtwField) -> Value {
    //             match field.in_type {
    //                 EtwInType::UnicodeString
    //                 | EtwInType::AnsiString
    //                 | EtwInType::CountedString
    //                 | EtwInType::CountedAnsiString => {
    //                     json!({
    //                         "type": "text",
    //                         "fields": {
    //                             "keyword": {
    //                                 "type": "keyword",
    //                                 "ignore_above": 256
    //                             }
    //                         }
    //                     })
    //                 }
    //                 EtwInType::Int8
    //                 | EtwInType::Uint8
    //                 | EtwInType::Int16
    //                 | EtwInType::Uint16
    //                 | EtwInType::Int32 => {
    //                     json!({ "type": "integer" })
    //                 }
    //                 EtwInType::Uint32 | EtwInType::Int64 => json!({ "type": "long" }),
    //                 EtwInType::Uint64 | EtwInType::FileTime => {
    //                     json!({ "type": "unsigned_long" })
    //                 }
    //                 // Pointers and Hex types are now Strings in JSON, so map to keyword
    //                 EtwInType::Pointer | EtwInType::HexInt32 | EtwInType::HexInt64 => {
    //                     json!({ "type": "keyword" })
    //                 }
    //                 EtwInType::Float => json!({ "type": "float" }),
    //                 EtwInType::Double => json!({ "type": "double" }),
    //                 EtwInType::Boolean => json!({ "type": "boolean" }),
    //                 EtwInType::Guid | EtwInType::Sid => json!({ "type": "keyword" }),
    //                 EtwInType::SystemTime => json!({ "type": "date" }),
    //                 EtwInType::Binary | EtwInType::CountedBinary => json!({ "type": "binary" }),
    //                 _ => {
    //                     json!({
    //                         "type": "keyword",
    //                         "doc_values": false
    //                     })
    //                 }
    //             }
    //         }
    //         json!({ "type": "unsigned_long" })
    //     }
    //     EtwInType::Float => json!({ "type": "float" }),
    //     EtwInType::Double => json!({ "type": "double" }),
    //     EtwInType::Boolean => json!({ "type": "boolean" }),
    //     EtwInType::Guid | EtwInType::Sid => json!({ "type": "keyword" }),
    //     EtwInType::SystemTime => json!({ "type": "date" }),
    //     EtwInType::Binary | EtwInType::CountedBinary => json!({ "type": "binary" }),
    //     _ => {
    //         json!({
    //             "type": "keyword",
    //             "doc_values": false
    //         })
    //     }
    // }
    json!({ "type": "keyword", "doc_values": false })
}
