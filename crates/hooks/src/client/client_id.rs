#[cfg(target_pointer_width = "32")]
use core::ffi::{c_char, c_void};
#[cfg(target_pointer_width = "32")]
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
#[cfg(target_pointer_width = "32")]
use std::sync::OnceLock;

#[cfg(target_pointer_width = "32")]
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};
#[cfg(target_pointer_width = "32")]
use tracing::{debug, info, warn};
use vapor_forge_patterns::registry::PatternRegistry;

#[cfg(target_pointer_width = "32")]
use vapor_forge_hook_engine::detour;
use vapor_forge_hook_engine::detour::CodeRegion;

#[cfg(target_pointer_width = "32")]
const ACCESS_PATTERN: &str = "CConfigStore::ClientIDConfigAccess";
#[cfg(target_pointer_width = "32")]
const INSTALL_CONFIG_STORE: u32 = 1;
#[cfg(target_pointer_width = "32")]
const SET_UINT64_SLOT_OFFSET: u64 = 0x2c;
#[cfg(target_pointer_width = "32")]
const CLIENT_ID_KEY: &[u8] = b"streaming/ClientID\0";

#[cfg(target_pointer_width = "32")]
const CAPTURE_PENDING: u8 = 0;
#[cfg(target_pointer_width = "32")]
const CAPTURE_RUNNING: u8 = 1;
#[cfg(target_pointer_width = "32")]
const CAPTURE_COMPLETE: u8 = 2;

#[cfg(target_pointer_width = "32")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Accessor {
    root_slot: usize,
    store_offset: usize,
    getter_slot: usize,
}

#[cfg(target_pointer_width = "32")]
#[derive(Debug, Eq, PartialEq)]
struct SiteLayout {
    pic_register: Register,
    root_displacement: i32,
    store_offset: usize,
    key_references: Vec<KeyReference>,
}

#[cfg(target_pointer_width = "32")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyReference {
    Direct(i32),
    Indirect(i32),
}

#[cfg(target_pointer_width = "32")]
#[derive(Clone, Debug)]
struct Mapping {
    start: usize,
    end: usize,
    readable: bool,
    executable: bool,
    steamclient: bool,
}

#[cfg(target_pointer_width = "32")]
static ACCESSOR: OnceLock<Accessor> = OnceLock::new();
#[cfg(target_pointer_width = "32")]
static CAPTURE_STATE: AtomicU8 = AtomicU8::new(CAPTURE_PENDING);
#[cfg(target_pointer_width = "32")]
static LAST_ATTEMPT_SECOND: AtomicU32 = AtomicU32::new(0);

pub(crate) fn resolve(registry: &PatternRegistry, code: &CodeRegion) {
    #[cfg(target_pointer_width = "32")]
    resolve_x86(registry, code);

    #[cfg(not(target_pointer_width = "32"))]
    {
        let _ = (registry, code);
    }
}

#[cfg(target_pointer_width = "32")]
fn resolve_x86(registry: &PatternRegistry, code: &CodeRegion) {
    let Some(entry) = registry.get(ACCESS_PATTERN) else {
        warn!(
            pattern = ACCESS_PATTERN,
            "ClientID access pattern is missing"
        );
        return;
    };
    let Some(site_address) = detour::resolve_pattern_entry(code, ACCESS_PATTERN, &entry) else {
        return;
    };
    let Some(site_offset) = site_address.checked_sub(code.base) else {
        return;
    };
    let Some(site_bytes) = code.bytes.get(site_offset..site_offset.saturating_add(160)) else {
        warn!(
            pattern = ACCESS_PATTERN,
            "ClientID access site is truncated"
        );
        return;
    };
    let Some(layout) = parse_site(site_bytes, site_address) else {
        warn!(
            pattern = ACCESS_PATTERN,
            "ClientID access site validation failed"
        );
        return;
    };
    let Some(pic_anchor) =
        find_pic_anchor(code.base, code.bytes, site_address, layout.pic_register)
    else {
        warn!(
            pattern = ACCESS_PATTERN,
            "ClientID PIC anchor was not resolved"
        );
        return;
    };
    let root_slot = add_x86_displacement(pic_anchor, layout.root_displacement);
    let Some(mappings) = read_mappings() else {
        warn!(
            pattern = ACCESS_PATTERN,
            "ClientID memory mappings are unavailable"
        );
        return;
    };
    if !is_readable(root_slot, std::mem::size_of::<usize>(), &mappings) {
        warn!(
            pattern = ACCESS_PATTERN,
            root_slot = format_args!("0x{root_slot:x}"),
            "ClientID config root slot is not readable"
        );
        return;
    }
    if !layout
        .key_references
        .iter()
        .copied()
        .any(|reference| key_reference_matches(pic_anchor, reference, &mappings))
    {
        warn!(
            pattern = ACCESS_PATTERN,
            "ClientID key reference validation failed"
        );
        return;
    }
    let Some(getter_slot) = crate::vtable_scan::slot_of("IClientConfigStore", "GetUint64") else {
        warn!(
            pattern = ACCESS_PATTERN,
            "IClientConfigStore::GetUint64 slot was not resolved"
        );
        return;
    };

    let accessor = Accessor {
        root_slot,
        store_offset: layout.store_offset,
        getter_slot,
    };
    if ACCESSOR.set(accessor).is_ok() {
        debug!(
            root_slot = format_args!("0x{:x}", accessor.root_slot),
            store_offset = format_args!("0x{:x}", accessor.store_offset),
            getter_slot = accessor.getter_slot,
            "ClientID CConfigStore access resolved"
        );
    }
}

pub(crate) fn refresh_device_descriptor() {
    #[cfg(target_pointer_width = "32")]
    refresh_device_descriptor_x86();
}

#[cfg(target_pointer_width = "32")]
fn refresh_device_descriptor_x86() {
    if CAPTURE_STATE.load(Ordering::Acquire) == CAPTURE_COMPLETE {
        return;
    }
    let now = unix_time_seconds();
    if LAST_ATTEMPT_SECOND.swap(now, Ordering::AcqRel) == now {
        return;
    }
    if CAPTURE_STATE
        .compare_exchange(
            CAPTURE_PENDING,
            CAPTURE_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }

    let client_id = ACCESSOR
        .get()
        .and_then(|accessor| read_mappings().and_then(|maps| read_client_id(*accessor, &maps)));
    let Some(client_id) = client_id else {
        CAPTURE_STATE.store(CAPTURE_PENDING, Ordering::Release);
        return;
    };

    vapor_forge_cloud_core::record_local_client_id(client_id);
    CAPTURE_STATE.store(CAPTURE_COMPLETE, Ordering::Release);
    info!(client_id, "Steam ClientID read from CConfigStore");
}

#[cfg(target_pointer_width = "32")]
fn read_client_id(accessor: Accessor, mappings: &[Mapping]) -> Option<u64> {
    if !is_readable(accessor.root_slot, std::mem::size_of::<usize>(), mappings) {
        return None;
    }
    // SAFETY: root_slot was derived from the validated PIC site and is readable.
    let root = unsafe { (accessor.root_slot as *const usize).read_unaligned() };
    let store = root.checked_add(accessor.store_offset)?;
    if root == 0 || !is_readable(store, std::mem::size_of::<usize>(), mappings) {
        return None;
    }
    // SAFETY: store points to a readable CConfigStore object.
    let vtable = unsafe { (store as *const usize).read_unaligned() };
    let getter_slot = vtable.checked_add(accessor.getter_slot * std::mem::size_of::<usize>())?;
    if vtable == 0 || !is_readable_steamclient(getter_slot, std::mem::size_of::<usize>(), mappings)
    {
        return None;
    }
    // SAFETY: getter_slot is readable and belongs to the live CConfigStore vtable.
    let getter_address = unsafe { (getter_slot as *const usize).read_unaligned() };
    if !is_executable_steamclient(getter_address, mappings) {
        return None;
    }

    type GetUint64Fn = unsafe extern "C" fn(*mut c_void, u32, *const c_char, u64) -> u64;
    // SAFETY: slot 3 is CConfigStore::GetUint64 for the validated object.
    let getter: GetUint64Fn = unsafe { std::mem::transmute(getter_address) };
    // SAFETY: getter is the validated 32-bit CConfigStore function and all
    // arguments remain live for this call.
    let value = unsafe {
        getter(
            store as *mut c_void,
            INSTALL_CONFIG_STORE,
            CLIENT_ID_KEY.as_ptr().cast(),
            0,
        )
    };
    (value != 0).then_some(value)
}

#[cfg(target_pointer_width = "32")]
fn parse_site(bytes: &[u8], address: usize) -> Option<SiteLayout> {
    let mut decoder = Decoder::with_ip(32, bytes, address as u64, DecoderOptions::NONE);
    let mut address_candidates = Vec::new();
    let mut root_register = None;
    let mut pic_register = None;
    let mut root_displacement = None;
    let mut store_register = None;
    let mut store_offset = None;
    let mut vtable_register = None;
    let mut key_references = Vec::new();
    let mut setter_register = None;
    let mut setter_call_validated = false;

    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_kind() == OpKind::Register
            && instruction.memory_base() != Register::None
            && instruction.memory_index() == Register::None
        {
            address_candidates.push((
                instruction.op0_register(),
                instruction.memory_base(),
                instruction.memory_displacement32() as i32,
            ));
        }
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == instruction.memory_base()
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() == 0
        {
            let register = instruction.op0_register();
            if let Some((_, base, displacement)) = address_candidates
                .iter()
                .rev()
                .find(|(destination, _, _)| *destination == register)
                .copied()
            {
                root_register = Some(register);
                pic_register = Some(base);
                root_displacement = Some(displacement);
            }
            continue;
        }
        if let Some(root) = root_register {
            if store_offset.is_none()
                && instruction.mnemonic() == Mnemonic::Lea
                && instruction.op0_kind() == OpKind::Register
                && instruction.memory_base() == root
                && instruction.memory_index() == Register::None
            {
                let displacement = instruction.memory_displacement64();
                if displacement <= 0x10_000 {
                    store_register = Some(instruction.op0_register());
                    store_offset = Some(displacement as usize);
                }
                continue;
            }
        }
        if let (Some(root), Some(expected_offset), Some(_)) =
            (root_register, store_offset, store_register)
        {
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.memory_base() == root
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == expected_offset as u64
            {
                vtable_register = Some(instruction.op0_register());
                continue;
            }
        }
        if let (Some(_), Some(vtable)) = (store_offset, vtable_register) {
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.memory_base() == vtable
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == SET_UINT64_SLOT_OFFSET
            {
                setter_register = Some(instruction.op0_register());
            }
        }
        if let Some(pic) = pic_register {
            if instruction.op0_kind() == OpKind::Register
                && instruction.memory_base() == pic
                && instruction.memory_index() == Register::None
            {
                let displacement = instruction.memory_displacement32() as i32;
                match instruction.mnemonic() {
                    Mnemonic::Lea => key_references.push(KeyReference::Direct(displacement)),
                    Mnemonic::Mov => key_references.push(KeyReference::Indirect(displacement)),
                    _ => {}
                }
            }
        }
        if setter_register.is_some_and(|setter| {
            instruction.flow_control() == FlowControl::IndirectCall
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register() == setter
        }) {
            setter_call_validated = true;
        }
    }
    if !setter_call_validated {
        return None;
    }
    Some(SiteLayout {
        pic_register: pic_register?,
        root_displacement: root_displacement?,
        store_offset: store_offset?,
        key_references,
    })
}

#[cfg(target_pointer_width = "32")]
fn key_reference_matches(pic_anchor: usize, reference: KeyReference, mappings: &[Mapping]) -> bool {
    let address = match reference {
        KeyReference::Direct(displacement) => add_x86_displacement(pic_anchor, displacement),
        KeyReference::Indirect(displacement) => {
            let slot = add_x86_displacement(pic_anchor, displacement);
            if !is_readable_steamclient(slot, std::mem::size_of::<usize>(), mappings) {
                return false;
            }
            // SAFETY: the complete pointer slot is in a readable steamclient mapping.
            unsafe { (slot as *const usize).read_unaligned() }
        }
    };
    memory_equals(address, CLIENT_ID_KEY, mappings)
}

#[cfg(target_pointer_width = "32")]
fn find_pic_anchor(
    code_base: usize,
    code: &[u8],
    site_address: usize,
    pic_register: Register,
) -> Option<usize> {
    let site_offset = site_address.checked_sub(code_base)?;
    let register_code = x86_register_code(pic_register)?;
    let start = site_offset.saturating_sub(256);
    for call_offset in (start..site_offset).rev() {
        if code.get(call_offset) != Some(&0xe8) {
            continue;
        }
        let Some(relative) = read_i32(code, call_offset + 1) else {
            continue;
        };
        let after_call = (code_base as u32)
            .wrapping_add(call_offset as u32)
            .wrapping_add(5);
        let target = after_call.wrapping_add(relative as u32) as usize;
        let Some(target_offset) = target.checked_sub(code_base) else {
            continue;
        };
        let Some(thunk) = code.get(target_offset..target_offset + 4) else {
            continue;
        };
        if thunk[0] != 0x8b
            || thunk[1] & 0xc7 != 0x04
            || (thunk[1] >> 3) & 7 != register_code
            || thunk[2] != 0x24
            || thunk[3] != 0xc3
        {
            continue;
        }
        let add_offset = call_offset + 5;
        let immediate = if register_code == 0 && code.get(add_offset) == Some(&0x05) {
            let Some(immediate) = read_u32(code, add_offset + 1) else {
                continue;
            };
            immediate
        } else if code.get(add_offset) == Some(&0x81)
            && code.get(add_offset + 1) == Some(&(0xc0 | register_code))
        {
            let Some(immediate) = read_u32(code, add_offset + 2) else {
                continue;
            };
            immediate
        } else {
            continue;
        };
        return Some(after_call.wrapping_add(immediate) as usize);
    }
    None
}

#[cfg(target_pointer_width = "32")]
fn add_x86_displacement(address: usize, displacement: i32) -> usize {
    (address as u32).wrapping_add(displacement as u32) as usize
}

#[cfg(target_pointer_width = "32")]
fn unix_time_seconds() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

#[cfg(target_pointer_width = "32")]
fn x86_register_code(register: Register) -> Option<u8> {
    match register {
        Register::EAX => Some(0),
        Register::ECX => Some(1),
        Register::EDX => Some(2),
        Register::EBX => Some(3),
        Register::ESP => Some(4),
        Register::EBP => Some(5),
        Register::ESI => Some(6),
        Register::EDI => Some(7),
        _ => None,
    }
}

#[cfg(target_pointer_width = "32")]
fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(target_pointer_width = "32")]
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(target_pointer_width = "32")]
fn read_mappings() -> Option<Vec<Mapping>> {
    let contents = std::fs::read_to_string("/proc/self/maps").ok()?;
    Some(contents.lines().filter_map(parse_mapping).collect())
}

#[cfg(target_pointer_width = "32")]
fn parse_mapping(line: &str) -> Option<Mapping> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let permissions = parts.next()?;
    parts.next()?;
    parts.next()?;
    parts.next()?;
    let path = parts.next().unwrap_or_default();
    let (start, end) = range.split_once('-')?;
    Some(Mapping {
        start: usize::from_str_radix(start, 16).ok()?,
        end: usize::from_str_radix(end, 16).ok()?,
        readable: permissions.starts_with('r'),
        executable: permissions.contains('x'),
        steamclient: path.rsplit('/').next() == Some("steamclient.so"),
    })
}

#[cfg(target_pointer_width = "32")]
fn is_readable(address: usize, length: usize, mappings: &[Mapping]) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    mappings
        .iter()
        .any(|mapping| mapping.readable && address >= mapping.start && end <= mapping.end)
}

#[cfg(target_pointer_width = "32")]
fn is_readable_steamclient(address: usize, length: usize, mappings: &[Mapping]) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    mappings.iter().any(|mapping| {
        mapping.readable && mapping.steamclient && address >= mapping.start && end <= mapping.end
    })
}

#[cfg(target_pointer_width = "32")]
fn is_executable_steamclient(address: usize, mappings: &[Mapping]) -> bool {
    mappings.iter().any(|mapping| {
        mapping.executable
            && mapping.steamclient
            && address >= mapping.start
            && address < mapping.end
    })
}

#[cfg(target_pointer_width = "32")]
fn memory_equals(address: usize, expected: &[u8], mappings: &[Mapping]) -> bool {
    if !is_readable_steamclient(address, expected.len(), mappings) {
        return false;
    }
    // SAFETY: the complete range was checked against a readable mapping.
    unsafe { std::slice::from_raw_parts(address as *const u8, expected.len()) == expected }
}

#[cfg(all(test, target_pointer_width = "32"))]
mod tests {
    use super::*;

    #[test]
    fn parses_client_id_config_access_site() {
        let bytes = [
            0x8d, 0x8b, 0x7c, 0xa0, 0x03, 0x00, // lea ecx,[ebx+root]
            0x80, 0xbe, 0x0e, 0x06, 0x00, 0x00, 0x00, // cmp byte [esi+...],0
            0x8b, 0x09, // mov ecx,[ecx]
            0x8d, 0xb9, 0x60, 0x0d, 0x00, 0x00, // lea edi,[ecx+0xd60]
            0x8b, 0x89, 0x60, 0x0d, 0x00, 0x00, // mov ecx,[ecx+0xd60]
            0x8b, 0x69, 0x2c, // mov ebp,[ecx+0x2c]
            0x8d, 0x8b, 0x43, 0x65, 0xee, 0xfd, // site-license key
            0x75, 0x06, // jne
            0x8d, 0x8b, 0x70, 0x59, 0xf0, 0xfd, // streaming key
            0xff, 0xd5, // call ebp
        ];
        let layout = parse_site(&bytes, 0x1000).expect("site should parse");
        assert_eq!(layout.pic_register, Register::EBX);
        assert_eq!(layout.root_displacement, 0x3a07c);
        assert_eq!(layout.store_offset, 0xd60);
        assert_eq!(layout.key_references.len(), 2);
    }

    #[test]
    fn parses_got_indirect_client_id_keys() {
        let bytes = [
            0x8d, 0x8b, 0x50, 0xb2, 0x03, 0x00, // lea ecx,[ebx+root]
            0x8b, 0x09, // mov ecx,[ecx]
            0x8d, 0xb9, 0x60, 0x0d, 0x00, 0x00, // lea edi,[ecx+0xd60]
            0x8b, 0x89, 0x60, 0x0d, 0x00, 0x00, // mov ecx,[ecx+0xd60]
            0x8b, 0x49, 0x2c, // mov ecx,[ecx+0x2c]
            0x8b, 0xab, 0x34, 0x55, 0x00, 0x00, // mov ebp,[ebx+site key slot]
            0xff, 0xd1, // call ecx
            0x8b, 0xab, 0x30, 0x55, 0x00, 0x00, // mov ebp,[ebx+streaming key slot]
        ];
        let layout = parse_site(&bytes, 0x1000).expect("site should parse");

        assert_eq!(layout.pic_register, Register::EBX);
        assert_eq!(layout.store_offset, 0xd60);
        assert_eq!(
            layout.key_references,
            vec![
                KeyReference::Indirect(0x5534),
                KeyReference::Indirect(0x5530)
            ]
        );
    }

    #[test]
    fn recovers_pic_anchor_from_matching_thunk_register() {
        let base = 0x1000usize;
        let call_offset = 4usize;
        let site_offset = 0x40usize;
        let thunk_offset = 0x80usize;
        let mut code = vec![0x90; 0xa0];
        code[call_offset] = 0xe8;
        let after_call = base + call_offset + 5;
        let relative = (base + thunk_offset) as i32 - after_call as i32;
        code[call_offset + 1..call_offset + 5].copy_from_slice(&relative.to_le_bytes());
        code[call_offset + 5..call_offset + 7].copy_from_slice(&[0x81, 0xc3]);
        code[call_offset + 7..call_offset + 11].copy_from_slice(&0x2000u32.to_le_bytes());
        code[thunk_offset..thunk_offset + 4].copy_from_slice(&[0x8b, 0x1c, 0x24, 0xc3]);

        assert_eq!(
            find_pic_anchor(base, &code, base + site_offset, Register::EBX),
            Some(after_call + 0x2000)
        );
    }
}
