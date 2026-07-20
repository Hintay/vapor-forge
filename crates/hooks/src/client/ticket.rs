use core::ffi::c_void;
use std::sync::OnceLock;

use tracing::{debug, info, warn};
use vapor_forge_config::AppId;
use vapor_forge_hook_engine::detour::Detour;

use super::install::{config, effective_ticket_mode, runtime_snapshot, TICKET_CACHE};
use vapor_forge_hook_engine::original::detour_or_return;

pub(crate) const TICKET_EXT_DATA_NAME: &str = "IClientUser::GetAppOwnershipTicketExtendedData";
pub(crate) const UPDATE_TICKET_NAME: &str = "IClientUser::BUpdateAppOwnershipTicket";
pub(crate) const IS_SUBSCRIBED_IN_TICKET_NAME: &str = "IClientUser::IsUserSubscribedAppInTicket";

// ---------------------------------------------------------------------------
// Function type aliases
// ---------------------------------------------------------------------------

pub(crate) type TicketExtDataFn = unsafe extern "C" fn(
    *mut c_void, // this (CUser implementation)
    u32,         // app_id
    *mut u8,     // p_ticket buffer
    u32,         // ticket_buf_size
    *mut u32,    // pi_app_id (out)
    *mut u32,    // pi_steam_id (out)
    *mut u32,    // pi_signature (out)
    *mut u32,    // pcb_signature (out)
) -> u32;
pub(crate) type UpdateTicketFn = unsafe extern "C" fn(*mut c_void, u32, bool) -> u32;
#[cfg(target_pointer_width = "32")]
pub(crate) type IsSubscribedInTicketFn =
    unsafe extern "C" fn(*mut c_void, u32, u32, *const u64, u32) -> u8;
#[cfg(target_pointer_width = "64")]
pub(crate) type IsSubscribedInTicketFn =
    unsafe extern "C" fn(*mut c_void, u64, *const u64, u32) -> u8;
const USER_HAS_LICENSE_FOR_APP_RESULT_HAS_LICENSE: u8 = 0;

pub(crate) fn resolve_adapter_implementation(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    name: &str,
    entry: usize,
    check_ownership: Option<usize>,
) -> Option<usize> {
    if name == IS_SUBSCRIBED_IN_TICKET_NAME && !validate_is_subscribed_wrapper_abi(code, entry) {
        return None;
    }
    if name == super::eticket::GET_ENCRYPTED_NAME {
        return resolve_get_enc_implementation(code, entry);
    }
    if name != IS_SUBSCRIBED_IN_TICKET_NAME
        && validate_direct_adapter_entry(code, name, entry, check_ownership)
    {
        return Some(entry);
    }
    let mut targets = direct_branch_targets(code, entry, 0x180)
        .into_iter()
        .filter(|&target| validate_direct_adapter_entry(code, name, target, check_ownership))
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets.dedup();
    if targets.len() == 1 {
        targets.first().copied()
    } else {
        None
    }
}

fn resolve_get_enc_implementation(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    entry: usize,
) -> Option<usize> {
    let target = get_enc_thunk_target(code, entry)?;
    let offset = target.checked_sub(code.base)?;
    validate_get_enc(code.bytes, offset).then_some(target)
}

#[cfg(target_pointer_width = "32")]
fn get_enc_thunk_target(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    entry: usize,
) -> Option<usize> {
    const ADJUST_THIS: &[u8] = &[0x81, 0x6c, 0x24, 0x04, 0xd4, 0x18, 0x00, 0x00];
    relative_tail_jump_after(code, entry, ADJUST_THIS)
}

#[cfg(target_pointer_width = "64")]
fn get_enc_thunk_target(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    entry: usize,
) -> Option<usize> {
    const ADJUST_THIS: &[u8] = &[0x48, 0x81, 0xef, 0xd0, 0x1f, 0x00, 0x00];
    relative_tail_jump_after(code, entry, ADJUST_THIS)
}

fn relative_tail_jump_after(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    entry: usize,
    prefix: &[u8],
) -> Option<usize> {
    let offset = entry.checked_sub(code.base)?;
    let jump = offset.checked_add(prefix.len())?;
    let bytes = code.bytes.get(offset..jump.checked_add(5)?)?;
    if !bytes.starts_with(prefix) || bytes.get(prefix.len()) != Some(&0xe9) {
        return None;
    }
    let displacement = i32::from_le_bytes(
        bytes
            .get(prefix.len() + 1..prefix.len() + 5)?
            .try_into()
            .ok()?,
    );
    let target = entry
        .checked_add(prefix.len() + 5)?
        .checked_add_signed(displacement as isize)?;
    (target >= code.base && target < code.base.checked_add(code.bytes.len())?).then_some(target)
}

#[cfg(target_pointer_width = "32")]
fn validate_is_subscribed_wrapper_abi(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    entry: usize,
) -> bool {
    let Some(offset) = entry.checked_sub(code.base) else {
        return false;
    };
    let Some(bytes) = code
        .bytes
        .get(offset..code.bytes.len().min(offset.saturating_add(0x180)))
    else {
        return false;
    };
    (has_seq(bytes, &[0x81, 0xee, 0xd4, 0x18, 0x00, 0x00])
        || has_seq(bytes, &[0x2d, 0xd4, 0x18, 0x00, 0x00])
        || has_seq(bytes, &[0x2d, 0xd8, 0x18, 0x00, 0x00]))
        && bytes
            .windows(4)
            .any(|window| window[0..3] == [0x8d, 0x44, 0x24])
}

#[cfg(target_pointer_width = "64")]
fn validate_is_subscribed_wrapper_abi(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    entry: usize,
) -> bool {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};

    let Some(offset) = entry.checked_sub(code.base) else {
        return false;
    };
    let Some(bytes) = code
        .bytes
        .get(offset..code.bytes.len().min(offset.saturating_add(0x180)))
    else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, bytes, entry as u64, DecoderOptions::NONE);
    let mut app_id_aliases = std::collections::HashSet::from([Register::EDX]);
    let mut forwards_app_id = false;
    let mut constructs_game_id = false;
    let mut adjusts_this = false;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        if instruction.mnemonic() == Mnemonic::Mov && instruction.op0_kind() == OpKind::Register {
            let destination = instruction.op0_register();
            if instruction.op1_kind() == OpKind::Register
                && app_id_aliases.contains(&instruction.op1_register())
            {
                app_id_aliases.insert(destination);
            } else if destination != Register::ECX {
                app_id_aliases.remove(&destination);
            }
            if destination == Register::ECX
                && instruction.op1_kind() == OpKind::Register
                && app_id_aliases.contains(&instruction.op1_register())
            {
                forwards_app_id = true;
            }
        }
        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_register() == Register::RDX
            && instruction.memory_base() == Register::RSP
        {
            constructs_game_id = true;
        }
        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_register() == Register::RDI
            && instruction.memory_displacement64() as i64 == -0x1fd0
        {
            adjusts_this = true;
        }
    }
    forwards_app_id && constructs_game_id && adjusts_this
}

pub(crate) fn validate_direct_adapter_entry(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    name: &str,
    target: usize,
    check_ownership: Option<usize>,
) -> bool {
    let Some(offset) = target.checked_sub(code.base) else {
        return false;
    };
    match name {
        TICKET_EXT_DATA_NAME => {
            validate_ticket_ext_data(code.bytes, offset)
                && ticket_ext_semantics_are_reachable(code, target)
        }
        UPDATE_TICKET_NAME => check_ownership
            .and_then(|address| address.checked_sub(code.base))
            .is_some_and(|check| validate_update_ticket(code.bytes, offset, check)),
        IS_SUBSCRIBED_IN_TICKET_NAME => validate_is_subscribed(code.bytes, offset),
        // GetEncryptedAppTicket resolves via resolve_get_enc_implementation.
        _ if name == super::eticket::REQUEST_ENCRYPTED_NAME => {
            validate_request_enc(code.bytes, offset)
        }
        _ => false,
    }
}

fn ticket_ext_semantics_are_reachable(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    target: usize,
) -> bool {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};

    #[cfg(target_pointer_width = "32")]
    const ADJUSTMENTS: &[&[u8]] = &[
        &[0x2d, 0xd4, 0x18, 0x00, 0x00],
        &[0x2d, 0xd8, 0x18, 0x00, 0x00],
    ];
    #[cfg(target_pointer_width = "64")]
    const ADJUSTMENTS: &[&[u8]] = &[
        &[0x49, 0x8d, 0xbc, 0x24, 0x30, 0xe0, 0xff, 0xff],
        &[0x48, 0x8d, 0xbb, 0x30, 0xe0, 0xff, 0xff],
    ];

    let Some(offset) = target.checked_sub(code.base) else {
        return false;
    };
    let Some(bytes) = code
        .bytes
        .get(offset..code.bytes.len().min(offset.saturating_add(0x160)))
    else {
        return false;
    };
    let reachable = reachable_instruction_offsets(bytes, target);
    let has_adjustment = ADJUSTMENTS.iter().any(|needle| {
        bytes
            .windows(needle.len())
            .enumerate()
            .any(|(index, window)| window == *needle && reachable.contains(&index))
    });
    let bitness = if cfg!(target_pointer_width = "64") {
        64
    } else {
        32
    };
    let mut has_mode4 = false;
    let mut has_call_after_mode4 = false;
    let mut has_high_stack_argument = false;
    let mut register_self_tests = 0usize;
    for &offset in &reachable {
        let mut decoder = Decoder::with_ip(
            bitness,
            &bytes[offset..],
            target.saturating_add(offset) as u64,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        if bytes.get(offset..offset + 2) == Some(&[0x6a, 0x04]) {
            has_mode4 = true;
        }
        if instruction.flow_control() == FlowControl::Call
            && reachable.iter().any(|&push| {
                bytes.get(push..push + 2) == Some(&[0x6a, 0x04])
                    && offset > push
                    && offset <= push + 0x30
            })
        {
            has_call_after_mode4 = true;
        }
        if matches!(instruction.memory_base(), Register::RSP | Register::ESP) {
            has_high_stack_argument |=
                (0x30..=0x100).contains(&(instruction.memory_displacement64() as usize));
        }
        if instruction.mnemonic() == Mnemonic::Test
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && instruction.op0_register() == instruction.op1_register()
        {
            register_self_tests += 1;
        }
    }
    has_adjustment
        && has_mode4
        && has_call_after_mode4
        && has_high_stack_argument
        && register_self_tests >= 2
}

fn reachable_instruction_offsets(bytes: &[u8], ip: usize) -> std::collections::HashSet<usize> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};

    let bitness = if cfg!(target_pointer_width = "64") {
        64
    } else {
        32
    };
    let mut pending = vec![0usize];
    let mut reachable = std::collections::HashSet::new();
    while let Some(offset) = pending.pop() {
        if offset >= bytes.len() || !reachable.insert(offset) {
            continue;
        }
        let mut decoder = Decoder::with_ip(
            bitness,
            &bytes[offset..],
            ip.saturating_add(offset) as u64,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        let next = offset.saturating_add(instruction.len());
        let branch_offset = instruction
            .near_branch_target()
            .checked_sub(ip as u64)
            .and_then(|target| usize::try_from(target).ok())
            .filter(|&target| target < bytes.len());
        match instruction.flow_control() {
            FlowControl::Return | FlowControl::IndirectBranch => {}
            FlowControl::UnconditionalBranch => {
                if let Some(target) = branch_offset {
                    pending.push(target);
                }
            }
            FlowControl::ConditionalBranch => {
                pending.push(next);
                if let Some(target) = branch_offset {
                    pending.push(target);
                }
            }
            _ => pending.push(next),
        }
    }
    reachable
}

fn direct_branch_targets(
    code: &vapor_forge_hook_engine::detour::CodeRegion,
    entry: usize,
    max_len: usize,
) -> Vec<usize> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};

    let Some(offset) = entry.checked_sub(code.base) else {
        return Vec::new();
    };
    let Some(bytes) = code
        .bytes
        .get(offset..code.bytes.len().min(offset.saturating_add(max_len)))
    else {
        return Vec::new();
    };
    let bitness = if cfg!(target_pointer_width = "64") {
        64
    } else {
        32
    };
    let mut decoder = Decoder::with_ip(bitness, bytes, entry as u64, DecoderOptions::NONE);
    let mut targets = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::UnconditionalBranch
        ) {
            let target = instruction.near_branch_target() as usize;
            if target >= code.base && target < code.base.saturating_add(code.bytes.len()) {
                targets.push(target);
            }
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::Return | FlowControl::UnconditionalBranch
        ) {
            break;
        }
    }
    targets
}

#[cfg(target_pointer_width = "32")]
fn validate_ticket_ext_data(code: &[u8], offset: usize) -> bool {
    let Some(bytes) = bounded_tail(code, offset, 0x160) else {
        return false;
    };
    has_seq(bytes, &[0x6a, 0x04])
        && (has_seq(bytes, &[0x2d, 0xd4, 0x18, 0x00, 0x00])
            || has_seq(bytes, &[0x2d, 0xd8, 0x18, 0x00, 0x00]))
        && has_call_after_mode4_push(bytes)
}

#[cfg(target_pointer_width = "64")]
fn validate_ticket_ext_data(code: &[u8], offset: usize) -> bool {
    let Some(bytes) = bounded_tail(code, offset, 0x100) else {
        return false;
    };
    let adjusts_this = has_seq(bytes, &[0x49, 0x8d, 0xbc, 0x24, 0x30, 0xe0, 0xff, 0xff])
        || has_seq(bytes, &[0x48, 0x8d, 0xbb, 0x30, 0xe0, 0xff, 0xff]);
    has_seq(bytes, &[0x6a, 0x04]) && adjusts_this && has_call_after_mode4_push(bytes)
}

#[cfg(target_pointer_width = "32")]
fn validate_update_ticket(code: &[u8], offset: usize, check_ownership: usize) -> bool {
    let Some(bytes) = bounded_tail(code, offset, 0x280) else {
        return false;
    };
    let receiver = has_seq(bytes, &[0x2d, 0xd4, 0x18, 0x00, 0x00])
        || has_seq(bytes, &[0x2d, 0xd8, 0x18, 0x00, 0x00])
        || has_seq(bytes, &[0x83, 0xb8, 0xf8, 0x00, 0x00, 0x00, 0x04]);
    has_seq(bytes, &[0x80, 0x7d, 0x10, 0x00])
        && bytes
            .windows(7)
            .any(|window| window[0] == 0xc7 && window[1] == 0x45 && window[3..] == [0xff; 4])
        && receiver
        && has_relative_call_to(code, offset, bytes.len(), check_ownership)
}

#[cfg(target_pointer_width = "64")]
fn validate_update_ticket(code: &[u8], offset: usize, check_ownership: usize) -> bool {
    let Some(bytes) = bounded_tail(code, offset, 0x330) else {
        return false;
    };
    let old_shape = has_seq(bytes, &[0x83, 0xbb, 0xe8, 0x01, 0x00, 0x00, 0x04])
        && has_seq(bytes, &[0xc7, 0x44, 0x24, 0x70, 0xff, 0xff, 0xff, 0xff])
        && has_seq(bytes, &[0xb9, 0x06, 0x00, 0x00, 0x00]);
    let current_shape = has_seq(bytes, &[0x83, 0xbb, 0x18, 0xe2, 0xff, 0xff, 0x04])
        && has_seq(bytes, &[0xc7, 0x44, 0x24, 0x20, 0xff, 0xff, 0xff, 0xff])
        && has_seq(bytes, &[0xb9, 0x07, 0x00, 0x00, 0x00]);
    has_seq(bytes, &[0x84, 0xd2])
        && (old_shape || current_shape)
        && has_relative_call_to(code, offset, bytes.len(), check_ownership)
}

#[cfg(target_pointer_width = "32")]
fn validate_is_subscribed(code: &[u8], offset: usize) -> bool {
    let Some(bytes) = bounded_tail(code, offset, 0x1f0) else {
        return false;
    };
    let status_filter = has_seq(bytes, &[0x83, 0xe2, 0xfd, 0x83, 0xfa, 0x01]);
    status_filter
        && [0u8, 1, 2]
            .into_iter()
            .all(|value| x86_has_stack_return_code(bytes, value))
        && !has_seq(bytes, &[0x89, 0x81, 0x84, 0x18, 0x00, 0x00])
}

#[cfg(target_pointer_width = "64")]
fn validate_is_subscribed(code: &[u8], offset: usize) -> bool {
    let Some(bytes) = bounded_tail(code, offset, 0x140) else {
        return false;
    };
    let status_filter = has_seq(bytes, &[0x83, 0xe2, 0xfd, 0x83, 0xfa, 0x01]);
    let old_returns = has_seq(bytes, &[0xbe, 0x02, 0x00, 0x00, 0x00])
        && has_seq(bytes, &[0xbe, 0x01, 0x00, 0x00, 0x00])
        && has_seq(bytes, &[0x31, 0xf6]);
    let current_returns = has_seq(bytes, &[0x41, 0xb8, 0x02, 0x00, 0x00, 0x00])
        && has_seq(bytes, &[0x41, 0xb8, 0x01, 0x00, 0x00, 0x00])
        && has_seq(bytes, &[0x45, 0x31, 0xc0]);
    status_filter
        && (old_returns || current_returns)
        && !has_seq(bytes, &[0x41, 0x89, 0x95, 0x60, 0x1f, 0x00, 0x00])
}

#[cfg(target_pointer_width = "32")]
fn validate_request_enc(code: &[u8], offset: usize) -> bool {
    let Some(bytes) = bounded_tail(code, offset, 0x160) else {
        return false;
    };
    ordered_reachable_sequences(
        bytes,
        offset,
        &[
            &[0x68, 0x70, 0x01, 0x00, 0x00],
            &[0x2d, 0xd4, 0x18, 0x00, 0x00],
            &[0xc7, 0x86, 0x6c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x89, 0x86, 0x68, 0x01, 0x00, 0x00],
            &[0x68, 0x7a, 0x07, 0x00, 0x00],
            &[0xff, 0x52, 0x14],
        ],
    )
}

#[cfg(target_pointer_width = "64")]
fn validate_request_enc(code: &[u8], offset: usize) -> bool {
    let Some(bytes) = bounded_tail(code, offset, 0x160) else {
        return false;
    };
    ordered_reachable_sequences(
        bytes,
        offset,
        &[
            &[0x48, 0x8d, 0xaf, 0x30, 0xe0, 0xff, 0xff],
            &[0xbf, 0xe8, 0x01, 0x00, 0x00],
            &[0x48, 0x89, 0xab, 0xd8, 0x01, 0x00, 0x00],
            &[
                0x48, 0xc7, 0x83, 0xe0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            &[0xb9, 0x7a, 0x07, 0x00, 0x00],
            &[0xff, 0x50, 0x28],
        ],
    )
}

#[cfg(target_pointer_width = "32")]
fn validate_get_enc(code: &[u8], offset: usize) -> bool {
    let Some(bytes) = bounded_tail(code, offset, 0x160) else {
        return false;
    };
    [
        (
            &[0x8b, 0x97, 0x50, 0x49, 0x00, 0x00][..],
            &[0x8b, 0x8f, 0x64, 0x49, 0x00, 0x00][..],
        ),
        (
            &[0x8b, 0x97, 0x14, 0x48, 0x00, 0x00][..],
            &[0x8b, 0x8f, 0x28, 0x48, 0x00, 0x00][..],
        ),
    ]
    .into_iter()
    .any(|(root, storage)| {
        ordered_reachable_sequences(
            bytes,
            offset,
            &[root, storage, &[0x6b, 0xd2, 0x44], &[0x8d, 0x7a, 0x18]],
        )
    })
}

#[cfg(target_pointer_width = "64")]
fn validate_get_enc(code: &[u8], offset: usize) -> bool {
    let Some(bytes) = bounded_tail(code, offset, 0x160) else {
        return false;
    };
    [
        (
            &[0x49, 0x63, 0x95, 0xd0, 0x62, 0x00, 0x00][..],
            &[0x49, 0x8b, 0x8d, 0xe8, 0x62, 0x00, 0x00][..],
        ),
        (
            &[0x49, 0x63, 0x95, 0x40, 0x61, 0x00, 0x00][..],
            &[0x49, 0x8b, 0x8d, 0x58, 0x61, 0x00, 0x00][..],
        ),
    ]
    .into_iter()
    .any(|(root, storage)| {
        ordered_reachable_sequences(
            bytes,
            offset,
            &[
                root,
                storage,
                &[0x48, 0x8d, 0x14, 0x52, 0x48, 0xc1, 0xe2, 0x05],
                &[0x4c, 0x8d, 0x6a, 0x20],
            ],
        )
    })
}

fn ordered_reachable_sequences(bytes: &[u8], ip: usize, needles: &[&[u8]]) -> bool {
    let reachable = reachable_instruction_offsets(bytes, ip);
    let mut cursor = 0usize;
    for &needle in needles {
        let Some(position) = bytes
            .windows(needle.len())
            .enumerate()
            .skip(cursor)
            .find_map(|(position, window)| {
                (window == needle && reachable.contains(&position)).then_some(position)
            })
        else {
            return false;
        };
        cursor = position.saturating_add(needle.len());
    }
    true
}

fn bounded_tail(code: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    code.get(offset..code.len().min(offset.saturating_add(len)))
}

fn has_seq(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

fn has_call_after_mode4_push(bytes: &[u8]) -> bool {
    bytes.windows(2).enumerate().any(|(index, window)| {
        window == [0x6a, 0x04] && bytes[index + 2..bytes.len().min(index + 0x30)].contains(&0xe8)
    })
}

fn has_relative_call_to(
    code: &[u8],
    function_offset: usize,
    max_len: usize,
    target_offset: usize,
) -> bool {
    let end = code.len().min(function_offset.saturating_add(max_len));
    (function_offset..end.saturating_sub(4)).any(|cursor| {
        if code[cursor] != 0xe8 {
            return false;
        }
        let Some(displacement) = code
            .get(cursor + 1..cursor + 5)
            .and_then(|bytes| bytes.try_into().ok())
            .map(i32::from_le_bytes)
        else {
            return false;
        };
        cursor
            .checked_add(5)
            .map(|next| next.wrapping_add_signed(displacement as isize))
            == Some(target_offset)
    })
}

#[cfg(target_pointer_width = "32")]
fn x86_has_stack_return_code(bytes: &[u8], value: u8) -> bool {
    bytes.windows(8).any(|window| {
        window[0] == 0xc7
            && window[1] == 0x44
            && window[2] == 0x24
            && window[4] == value
            && window[5..8] == [0, 0, 0]
    })
}

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

pub(crate) static mut TICKET_EXT_DATA_DETOUR: Option<Detour<TicketExtDataFn>> = None;
pub(crate) static mut UPDATE_TICKET_DETOUR: Option<Detour<UpdateTicketFn>> = None;
pub(crate) static mut IS_SUBSCRIBED_IN_TICKET_DETOUR: Option<Detour<IsSubscribedInTicketFn>> = None;
/// Source ticket from appId 7, lazily acquired on first derivation attempt.
pub(crate) static SOURCE_TICKET_7: OnceLock<Option<Vec<u8>>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Hook replacement functions: GetAppOwnershipTicketExtendedData (ticket forge)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "C" fn hk_ticket_ext_data(
    this: *mut c_void,
    app_id: u32,
    p_ticket: *mut u8,
    ticket_buf_size: u32,
    pi_app_id: *mut u32,
    pi_steam_id: *mut u32,
    pi_signature: *mut u32,
    pcb_signature: *mut u32,
) -> u32 {
    let runtime = runtime_snapshot();
    let authority = vapor_forge_features::apps::classify_app(&runtime.config, AppId(app_id));
    if authority.requires_injected_ownership() {
        return provide_local_ticket(
            this,
            app_id,
            p_ticket,
            ticket_buf_size,
            pi_app_id,
            pi_steam_id,
            pi_signature,
            pcb_signature,
            &runtime,
        );
    }

    // SAFETY: TICKET_EXT_DATA_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!(
        "GetAppOwnershipTicketExtendedData",
        TICKET_EXT_DATA_DETOUR,
        0
    );
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(
        this,
        app_id,
        p_ticket,
        ticket_buf_size,
        pi_app_id,
        pi_steam_id,
        pi_signature,
        pcb_signature,
    ) };

    // If Steam returned a valid ticket, cache it.
    // Persist decision:
    //   Controlled + delegate → always disk (cross-account)
    //   Controlled + forge   → never disk (re-acquirable)
    //   Uncontrolled (real)  → follows [ticket] cache setting
    if result > 0 && !p_ticket.is_null() {
        let size = result as usize;
        // SAFETY: p_ticket points to a buffer with at least `result` bytes written by Steam.
        let ticket_data = unsafe { std::slice::from_raw_parts(p_ticket, size) }.to_vec();
        let cfg = config();
        let persist = if cfg.is_controlled_app(AppId(app_id)) {
            effective_ticket_mode(&cfg, AppId(app_id)) == vapor_forge_config::TicketMode::Delegate
        } else {
            cfg.ticket.cache == vapor_forge_config::TicketCacheMode::Disk
        };
        TICKET_CACHE.store_app_ticket(AppId(app_id), ticket_data, persist);
        return result;
    }

    result
}

#[allow(clippy::too_many_arguments)] // Mirrors Steam's FFI output parameters.
fn provide_local_ticket(
    this: *mut c_void,
    app_id: u32,
    p_ticket: *mut u8,
    ticket_buf_size: u32,
    pi_app_id: *mut u32,
    pi_steam_id: *mut u32,
    pi_signature: *mut u32,
    pcb_signature: *mut u32,
    runtime: &super::install::RuntimeSnapshot,
) -> u32 {
    let cfg = &runtime.config;
    let ticket_mode = effective_ticket_mode(cfg, AppId(app_id));
    let ss = &runtime.script_state;

    // Delegate mode: while inside the initial request window, prefer the
    // cached ticket (from a previous owner session) over forging so the
    // ticket's embedded SteamID matches an account that actually owns the
    // app. Once the window closes, fall through to the normal forge path
    // and stop spoofing GetSteamID.
    if ticket_mode == vapor_forge_config::TicketMode::Delegate {
        if vapor_forge_features::ticket::in_delegate_window(AppId(app_id)) {
            if let Some(ticket) = TICKET_CACHE.get_app_ticket(AppId(app_id), &ss.app_tickets) {
                if let Some(steamid) = extract_steamid_from_ticket(&ticket) {
                    vapor_forge_features::ticket::set_delegate_steamid(steamid);
                }
                let Some(layout) = cached_ticket_layout(&ticket) else {
                    return 0;
                };
                return // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { copy_ticket_to_buffer(
                    &ticket,
                    &layout,
                    p_ticket,
                    ticket_buf_size,
                    pi_app_id,
                    pi_steam_id,
                    pi_signature,
                    pcb_signature,
                    app_id,
                    "delegate-cached",
                ) };
            }
            // No cached ticket available yet, fall through to forge below.
            debug!(
                app_id,
                "ticket: delegate window active but no cached ticket, forging"
            );
        } else {
            // Window closed: stop overriding GetSteamID so the rest of the
            // Steam session runs under the real user (matches OpenSteamTool's
            // DenuvoAuth `IsAuthorizedPipe` returning false past the window).
            vapor_forge_features::ticket::clear_delegate_steamid();
        }
    }

    // Try to provide a ticket from cache / Lua / forge
    if let Some(ticket) = TICKET_CACHE.get_app_ticket(AppId(app_id), &ss.app_tickets) {
        let Some(layout) = cached_ticket_layout(&ticket) else {
            return 0;
        };
        return // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { copy_ticket_to_buffer(
            &ticket,
            &layout,
            p_ticket,
            ticket_buf_size,
            pi_app_id,
            pi_steam_id,
            pi_signature,
            pcb_signature,
            app_id,
            "cached",
        ) };
    }

    // Forge from appId 7 source ticket. The forged ticket embeds the source
    // ticket's SteamID (usually the current user's, since appId 7 is owned by
    // whoever's logged in), so `GetSteamID` returning the real SteamID already
    // matches. Don't stamp `delegate_steamid` here — OpenSteamTool's
    // `IsAuthorizedPipe` is false past the DenuvoAuth window and its
    // GetSteamID handler falls through to the original.
    if let Some(forged) = try_forge_ticket(this, app_id) {
        let layout = TicketLayout {
            reported_size: forged.total_size,
            app_id_offset: forged.app_id_offset,
            steam_id_offset: forged.steam_id_offset,
            signature_offset: forged.signature_offset,
            signature_size: forged.signature_size,
        };
        return // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { copy_ticket_to_buffer(
            &forged.data,
            &layout,
            p_ticket,
            ticket_buf_size,
            pi_app_id,
            pi_steam_id,
            pi_signature,
            pcb_signature,
            app_id,
            "forged",
        ) };
    }

    debug!(
        app_id,
        "ticket: no ticket available (no cache, no source for forge)"
    );
    0
}

/// Extract the SteamID embedded in a raw ownership ticket, using the
/// standard `TICKET_STEAMID_OFFSET` (byte 8, little-endian u64). Returns
/// `None` if the ticket is too small to contain a SteamID field.
pub(crate) fn extract_steamid_from_ticket(ticket: &[u8]) -> Option<u64> {
    const STEAMID_OFFSET: usize = 8;
    let end = STEAMID_OFFSET.checked_add(8)?;
    let bytes: [u8; 8] = ticket.get(STEAMID_OFFSET..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

pub(crate) struct TicketLayout {
    pub reported_size: u32,
    pub app_id_offset: u32,
    pub steam_id_offset: u32,
    pub signature_offset: u32,
    pub signature_size: u32,
}

const SIGNATURE_SIZE_BYTES: u32 = 128;
const STEAM_ID_OFFSET: u32 = 8;
const APP_ID_OFFSET: u32 = 16;

/// Layout for a raw AppOwnershipTicket returned to us by Steam. Real Steam
/// tickets carry the signature offset as a little-endian u32 in the first four
/// bytes (SignedSize field); appId sits at the fixed header offset 16.
pub(crate) fn cached_ticket_layout(ticket: &[u8]) -> Option<TicketLayout> {
    let physical = u32::try_from(ticket.len()).ok()?;
    let header: [u8; 4] = ticket.get(..4)?.try_into().ok()?;
    let signature_offset = u32::from_le_bytes(header);
    if signature_offset.checked_add(SIGNATURE_SIZE_BYTES)? > physical {
        return None;
    }
    if APP_ID_OFFSET.checked_add(4)? > signature_offset {
        return None;
    }
    Some(TicketLayout {
        reported_size: physical,
        app_id_offset: APP_ID_OFFSET,
        steam_id_offset: STEAM_ID_OFFSET,
        signature_offset,
        signature_size: SIGNATURE_SIZE_BYTES,
    })
}

/// Copy ticket data into the output buffer, populate the offset pointers and
/// return the value Steam should see as the ticket size. Note that
/// `layout.reported_size` may be smaller than `ticket.len()` — the forge path
/// deliberately reports a size that excludes the extra appId inserted before
/// the signature, so the DRM's signature-coverage calculation lines up with
/// the source ticket's original signed span.
#[allow(clippy::too_many_arguments)] // Mirrors Steam's FFI output parameters.
/// # Safety
/// Every non-null output pointer must be valid and writable for its documented
/// value, and `p_ticket` must cover `buf_size` bytes.
pub(crate) unsafe fn copy_ticket_to_buffer(
    ticket: &[u8],
    layout: &TicketLayout,
    p_ticket: *mut u8,
    buf_size: u32,
    pi_app_id: *mut u32,
    pi_steam_id: *mut u32,
    pi_signature: *mut u32,
    pcb_signature: *mut u32,
    app_id: u32,
    source: &str,
) -> u32 {
    const STEAM_ID_END: usize = 16;
    let minimum_size = SIGNATURE_SIZE_BYTES as usize + 4;
    if p_ticket.is_null()
        || ticket.len() < minimum_size.max(STEAM_ID_END)
        || ticket.len() > buf_size as usize
    {
        return 0;
    }

    // SAFETY: p_ticket is a valid buffer of buf_size bytes, provided by Steam's caller.
    unsafe {
        std::ptr::copy_nonoverlapping(ticket.as_ptr(), p_ticket, ticket.len());
    }

    if !pi_app_id.is_null() {
        // SAFETY: pi_app_id is a valid pointer from Steam's caller.
        unsafe { *pi_app_id = layout.app_id_offset };
    }
    if !pi_steam_id.is_null() {
        // SAFETY: pi_steam_id is a valid pointer from Steam's caller.
        unsafe { *pi_steam_id = layout.steam_id_offset };
    }
    if !pi_signature.is_null() {
        // SAFETY: pi_signature is a valid pointer from Steam's caller.
        unsafe { *pi_signature = layout.signature_offset };
    }
    if !pcb_signature.is_null() {
        // SAFETY: pcb_signature is a valid pointer from Steam's caller.
        unsafe { *pcb_signature = layout.signature_size };
    }

    info!(
        app_id,
        physical = ticket.len(),
        reported = layout.reported_size,
        source,
        "ticket: provided to Steam"
    );
    layout.reported_size
}

/// Try to forge a ticket for `target_app_id` from the appId 7 source ticket.
pub(crate) fn try_forge_ticket(
    this: *mut c_void,
    target_app_id: u32,
) -> Option<vapor_forge_features::ticket::forge::ForgedTicket> {
    use vapor_forge_features::ticket::forge;

    let source = SOURCE_TICKET_7.get_or_init(|| acquire_source_ticket(this));

    let source_data = source.as_ref()?;
    let forged = forge::forge_from_source(source_data, target_app_id);
    if forged.is_some() {
        info!(target_app_id, "ticket: derived from appId 7 source");
    }
    forged
}

/// Acquire the source ticket (appId 7) by calling the original function directly.
pub(crate) fn acquire_source_ticket(this: *mut c_void) -> Option<Vec<u8>> {
    const BUF_SIZE: u32 = 4096;
    let mut buf = vec![0u8; BUF_SIZE as usize];
    let mut app_id_off: u32 = 0;
    let mut steam_id_off: u32 = 0;
    let mut sig_off: u32 = 0;
    let mut sig_size: u32 = 0;

    // SAFETY: TICKET_EXT_DATA_DETOUR is set before the hook is enabled.
    let original = unsafe {
        vapor_forge_hook_engine::original::original_detour(
            "GetAppOwnershipTicketExtendedData",
            std::ptr::addr_of!(TICKET_EXT_DATA_DETOUR),
        )
    }?;
    // SAFETY: the trampoline holds the original function's relocated prologue.
    let size = unsafe {
        original(
            this,
            vapor_forge_features::ticket::forge::SOURCE_APP_ID,
            buf.as_mut_ptr(),
            BUF_SIZE,
            &mut app_id_off,
            &mut steam_id_off,
            &mut sig_off,
            &mut sig_size,
        )
    };

    if size == 0 {
        warn!("ticket: failed to acquire source ticket (appId 7)");
        return None;
    }

    buf.truncate(size as usize);
    info!(size, "ticket: acquired source ticket from appId 7");
    Some(buf)
}

// ---------------------------------------------------------------------------
// Hook replacement functions: BUpdateAppOwnershipTicket
// ---------------------------------------------------------------------------

// Third arg is Steam's `bOnlyUpdateIfStale`: when true, skip the network
// round-trip if a fresh-enough ticket is already cached.
pub(crate) unsafe extern "C" fn hk_update_ticket(
    this: *mut c_void,
    app_id: u32,
    only_update_if_stale: bool,
) -> u32 {
    // Always forward to the trampoline so Steam's internal ticket cache and
    // the appId 7 source ticket both stay warm. For controlled apps that
    // don't have a cached ticket yet, clear `bOnlyUpdateIfStale` so the
    // trampoline actually re-fetches instead of no-oping.
    let cfg = config();
    let controlled =
        vapor_forge_features::apps::classify_app(&cfg, AppId(app_id)).requires_injected_ownership();
    let only_update_if_stale = if controlled && !TICKET_CACHE.has_app_ticket(AppId(app_id)) {
        debug!(
            app_id,
            "ticket: BUpdateAppOwnershipTicket forcing full refresh for uncached controlled app"
        );
        false
    } else {
        only_update_if_stale
    };

    // SAFETY: UPDATE_TICKET_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!("BUpdateAppOwnershipTicket", UPDATE_TICKET_DETOUR, 0);
    let result = // SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract.
unsafe { original(this, app_id, only_update_if_stale) };
    if controlled {
        // Real update will report failure for apps we don't own; force success
        // upward so the game side keeps making progress.
        debug!(
            app_id,
            result, "ticket: BUpdateAppOwnershipTicket forwarded for controlled app"
        );
        1
    } else {
        result
    }
}

// ---------------------------------------------------------------------------
// Hook replacement functions: IsUserSubscribedAppInTicket
// ---------------------------------------------------------------------------

#[cfg(target_pointer_width = "32")]
pub(crate) unsafe extern "C" fn hk_is_subscribed_in_ticket(
    this: *mut c_void,
    steam_id_low: u32,
    steam_id_high: u32,
    game_id_ptr: *const u64,
    app_id: u32,
) -> u8 {
    if is_controlled_unowned_ticket_app(app_id) {
        debug!(app_id, "ticket: IsUserSubscribedAppInTicket resolved");
        return USER_HAS_LICENSE_FOR_APP_RESULT_HAS_LICENSE;
    }

    // SAFETY: IS_SUBSCRIBED_IN_TICKET_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!(
        "IsUserSubscribedAppInTicket",
        IS_SUBSCRIBED_IN_TICKET_DETOUR,
        0
    );
    // SAFETY: the typed original and unchanged callback arguments satisfy the
    // validated 32-bit subscription ABI.
    unsafe { original(this, steam_id_low, steam_id_high, game_id_ptr, app_id) }
}

#[cfg(target_pointer_width = "64")]
pub(crate) unsafe extern "C" fn hk_is_subscribed_in_ticket(
    this: *mut c_void,
    steam_id: u64,
    game_id_ptr: *const u64,
    app_id: u32,
) -> u8 {
    if is_controlled_unowned_ticket_app(app_id) {
        debug!(app_id, "ticket: IsUserSubscribedAppInTicket resolved");
        return USER_HAS_LICENSE_FOR_APP_RESULT_HAS_LICENSE;
    }

    // SAFETY: IS_SUBSCRIBED_IN_TICKET_DETOUR set before hook enabled, never modified after.
    let original = detour_or_return!(
        "IsUserSubscribedAppInTicket",
        IS_SUBSCRIBED_IN_TICKET_DETOUR,
        0
    );
    /* SAFETY: the typed Steam function and arguments satisfy the active FFI callback contract. */
    unsafe { original(this, steam_id, game_id_ptr, app_id) }
}

fn is_controlled_unowned_ticket_app(app_id: u32) -> bool {
    let cfg = config();
    vapor_forge_features::apps::classify_app(&cfg, AppId(app_id)).requires_injected_ownership()
}

#[cfg(test)]
mod tests {
    use super::{cached_ticket_layout, copy_ticket_to_buffer};

    /// Build a plausible AppOwnershipTicket: 256-byte payload whose first four
    /// bytes carry the signature offset (128 = payload starts at 0, signature
    /// spans bytes 128..256).
    fn synthetic_ticket(size: usize, signature_offset: u32) -> Vec<u8> {
        let mut ticket = vec![0xAA; size];
        ticket[..4].copy_from_slice(&signature_offset.to_le_bytes());
        ticket
    }

    #[test]
    fn copy_ticket_rejects_short_ticket() {
        let ticket = vec![0xAA; 64];
        let layout = cached_ticket_layout(&synthetic_ticket(256, 128)).expect("layout");
        let mut output = vec![0u8; 256];
        assert_eq!(
            // SAFETY: output is a live writable Vec allocation and all optional
            // output pointers are null.
            unsafe {
                copy_ticket_to_buffer(
                    &ticket,
                    &layout,
                    output.as_mut_ptr(),
                    output.len() as u32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    480,
                    "test",
                )
            },
            0
        );
    }

    #[test]
    fn copy_ticket_rejects_truncation_and_reports_valid_offsets() {
        let ticket = synthetic_ticket(256, 128);
        let layout = cached_ticket_layout(&ticket).expect("layout");
        let mut short_output = vec![0u8; 128];
        assert_eq!(
            // SAFETY: short_output is a live writable Vec allocation and all
            // optional output pointers are null.
            unsafe {
                copy_ticket_to_buffer(
                    &ticket,
                    &layout,
                    short_output.as_mut_ptr(),
                    short_output.len() as u32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    480,
                    "test",
                )
            },
            0
        );

        let mut output = vec![0u8; ticket.len()];
        let (mut app, mut steam, mut signature, mut signature_size) = (0, 0, 0, 0);
        assert_eq!(
            // SAFETY: output and every scalar output pointer remain live and
            // writable for the duration of this call.
            unsafe {
                copy_ticket_to_buffer(
                    &ticket,
                    &layout,
                    output.as_mut_ptr(),
                    output.len() as u32,
                    &mut app,
                    &mut steam,
                    &mut signature,
                    &mut signature_size,
                    480,
                    "test",
                )
            },
            ticket.len() as u32
        );
        assert_eq!((app, steam, signature, signature_size), (16, 8, 128, 128));
        assert_eq!(output, ticket);
    }

    #[test]
    fn cached_layout_rejects_invalid_header() {
        assert!(cached_ticket_layout(&vec![0xAA; 256]).is_none());
    }
}

#[cfg(test)]
mod eticket_lowering_tests {
    use super::{resolve_adapter_implementation, validate_get_enc, validate_request_enc};
    use vapor_forge_hook_engine::detour::CodeRegion;

    const BASE: usize = 0x10_0000;
    const IMPL_OFFSET: usize = 0x80;

    fn body(chunks: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for chunk in chunks {
            bytes.extend_from_slice(chunk);
            bytes.extend_from_slice(&[0x90; 6]);
        }
        bytes.resize(0x180, 0x90);
        bytes
    }

    fn code_region(bytes: Vec<u8>) -> CodeRegion {
        CodeRegion {
            base: BASE,
            bytes: Box::leak(bytes.into_boxed_slice()),
        }
    }

    fn write_relative_branch(bytes: &mut [u8], opcode_offset: usize, target_offset: usize) {
        bytes[opcode_offset] = 0xe9;
        let next = opcode_offset + 5;
        let displacement = i32::try_from(target_offset as isize - next as isize).expect("rel32");
        bytes[opcode_offset + 1..opcode_offset + 5].copy_from_slice(&displacement.to_le_bytes());
    }

    fn get_thunk_region(prefix: &[u8], implementation: &[u8]) -> CodeRegion {
        let mut bytes = vec![0xcc; IMPL_OFFSET + implementation.len()];
        for entry in [0usize, 0x20] {
            bytes[entry..entry + prefix.len()].copy_from_slice(prefix);
            write_relative_branch(&mut bytes, entry + prefix.len(), IMPL_OFFSET);
        }
        bytes[IMPL_OFFSET..].copy_from_slice(implementation);
        code_region(bytes)
    }

    fn call_region(implementation: &[u8]) -> CodeRegion {
        let mut bytes = vec![0xcc; IMPL_OFFSET + implementation.len()];
        write_relative_branch(&mut bytes, 0, IMPL_OFFSET);
        bytes[0] = 0xe8;
        bytes[5] = 0xc3;
        bytes[IMPL_OFFSET..].copy_from_slice(implementation);
        code_region(bytes)
    }

    #[cfg(target_pointer_width = "64")]
    mod x64 {
        use super::{
            body, call_region, code_region, get_thunk_region, resolve_adapter_implementation,
            validate_get_enc, validate_request_enc, BASE, IMPL_OFFSET,
        };

        const ADJUST_THIS: &[u8] = &[0x48, 0x8d, 0xaf, 0x30, 0xe0, 0xff, 0xff];
        const ALLOC_JOB: &[u8] = &[0xbf, 0xe8, 0x01, 0x00, 0x00];
        const JOB_OWNER: &[u8] = &[0x48, 0x89, 0xab, 0xd8, 0x01, 0x00, 0x00];
        const JOB_MESSAGE_ZERO: &[u8] = &[
            0x48, 0xc7, 0x83, 0xe0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        const EMSG_ETICKET_REQUEST: &[u8] = &[0xb9, 0x7a, 0x07, 0x00, 0x00];
        const CM_BUILDER_CALL: &[u8] = &[0xff, 0x50, 0x28];
        const NODE_STRIDE: &[u8] = &[0x48, 0x8d, 0x14, 0x52, 0x48, 0xc1, 0xe2, 0x05];
        const TICKET_PAYLOAD: &[u8] = &[0x4c, 0x8d, 0x6a, 0x20];
        const GET_THUNK_ADJUST: &[u8] = &[0x48, 0x81, 0xef, 0xd0, 0x1f, 0x00, 0x00];

        fn request_body() -> Vec<u8> {
            body(&[
                ADJUST_THIS,
                ALLOC_JOB,
                JOB_OWNER,
                JOB_MESSAGE_ZERO,
                EMSG_ETICKET_REQUEST,
                CM_BUILDER_CALL,
            ])
        }

        fn public_get_body() -> Vec<u8> {
            body(&[
                &[0x49, 0x63, 0x95, 0xd0, 0x62, 0x00, 0x00],
                &[0x49, 0x8b, 0x8d, 0xe8, 0x62, 0x00, 0x00],
                NODE_STRIDE,
                TICKET_PAYLOAD,
            ])
        }

        #[test]
        fn request_enc_accepts_full_shape() {
            let bytes = request_body();
            assert!(validate_request_enc(&bytes, 0));
            let code = code_region(bytes);
            assert_eq!(
                resolve_adapter_implementation(
                    &code,
                    super::super::super::eticket::REQUEST_ENCRYPTED_NAME,
                    BASE,
                    None,
                ),
                Some(BASE)
            );
        }

        #[test]
        fn request_enc_rejects_missing_owner_link() {
            let bytes = body(&[
                ADJUST_THIS,
                ALLOC_JOB,
                JOB_MESSAGE_ZERO,
                EMSG_ETICKET_REQUEST,
                CM_BUILDER_CALL,
            ]);
            assert!(!validate_request_enc(&bytes, 0));
        }

        #[test]
        fn request_enc_rejects_anchors_after_return() {
            let bytes = body(&[
                ADJUST_THIS,
                ALLOC_JOB,
                &[0xc3],
                JOB_OWNER,
                JOB_MESSAGE_ZERO,
                EMSG_ETICKET_REQUEST,
                CM_BUILDER_CALL,
            ]);
            assert!(!validate_request_enc(&bytes, 0));
        }

        #[test]
        fn get_enc_accepts_public_and_publicbeta_offsets() {
            let public = public_get_body();
            let publicbeta = body(&[
                &[0x49, 0x63, 0x95, 0x40, 0x61, 0x00, 0x00],
                &[0x49, 0x8b, 0x8d, 0x58, 0x61, 0x00, 0x00],
                NODE_STRIDE,
                TICKET_PAYLOAD,
            ]);
            assert!(validate_get_enc(&public, 0));
            assert!(validate_get_enc(&publicbeta, 0));
        }

        #[test]
        fn get_enc_rejects_cross_build_offset_pair() {
            // public root + publicbeta storage is not a real build; must reject.
            let mixed = body(&[
                &[0x49, 0x63, 0x95, 0xd0, 0x62, 0x00, 0x00],
                &[0x49, 0x8b, 0x8d, 0x58, 0x61, 0x00, 0x00],
                NODE_STRIDE,
                TICKET_PAYLOAD,
            ]);
            assert!(!validate_get_enc(&mixed, 0));
        }

        #[test]
        fn get_enc_rejects_missing_stride() {
            let bytes = body(&[
                &[0x49, 0x63, 0x95, 0xd0, 0x62, 0x00, 0x00],
                &[0x49, 0x8b, 0x8d, 0xe8, 0x62, 0x00, 0x00],
                TICKET_PAYLOAD,
            ]);
            assert!(!validate_get_enc(&bytes, 0));
        }

        #[test]
        fn get_enc_rejects_reordered_map_operations() {
            let bytes = body(&[
                NODE_STRIDE,
                &[0x49, 0x63, 0x95, 0xd0, 0x62, 0x00, 0x00],
                &[0x49, 0x8b, 0x8d, 0xe8, 0x62, 0x00, 0x00],
                TICKET_PAYLOAD,
            ]);
            assert!(!validate_get_enc(&bytes, 0));
        }

        #[test]
        fn get_resolver_accepts_only_adjusting_tail_thunk() {
            let implementation = public_get_body();
            let code = get_thunk_region(GET_THUNK_ADJUST, &implementation);
            assert_eq!(
                resolve_adapter_implementation(
                    &code,
                    super::super::super::eticket::GET_ENCRYPTED_NAME,
                    BASE,
                    None,
                ),
                Some(BASE + IMPL_OFFSET)
            );
            assert_eq!(
                resolve_adapter_implementation(
                    &code,
                    super::super::super::eticket::GET_ENCRYPTED_NAME,
                    BASE + 0x20,
                    None,
                ),
                Some(BASE + IMPL_OFFSET)
            );

            let call = call_region(&implementation);
            assert_eq!(
                resolve_adapter_implementation(
                    &call,
                    super::super::super::eticket::GET_ENCRYPTED_NAME,
                    BASE,
                    None,
                ),
                None
            );
        }
    }

    #[cfg(target_pointer_width = "32")]
    mod x86 {
        use super::{
            body, call_region, code_region, get_thunk_region, resolve_adapter_implementation,
            validate_get_enc, validate_request_enc, BASE, IMPL_OFFSET,
        };

        const ALLOC_JOB: &[u8] = &[0x68, 0x70, 0x01, 0x00, 0x00];
        const ADJUST_THIS: &[u8] = &[0x2d, 0xd4, 0x18, 0x00, 0x00];
        const JOB_MESSAGE_ZERO: &[u8] =
            &[0xc7, 0x86, 0x6c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        const JOB_OWNER: &[u8] = &[0x89, 0x86, 0x68, 0x01, 0x00, 0x00];
        const EMSG_ETICKET_REQUEST: &[u8] = &[0x68, 0x7a, 0x07, 0x00, 0x00];
        const CM_BUILDER_CALL: &[u8] = &[0xff, 0x52, 0x14];
        const NODE_STRIDE: &[u8] = &[0x6b, 0xd2, 0x44];
        const TICKET_PAYLOAD: &[u8] = &[0x8d, 0x7a, 0x18];
        const GET_THUNK_ADJUST: &[u8] = &[0x81, 0x6c, 0x24, 0x04, 0xd4, 0x18, 0x00, 0x00];

        fn request_body() -> Vec<u8> {
            body(&[
                ALLOC_JOB,
                ADJUST_THIS,
                JOB_MESSAGE_ZERO,
                JOB_OWNER,
                EMSG_ETICKET_REQUEST,
                CM_BUILDER_CALL,
            ])
        }

        fn public_get_body() -> Vec<u8> {
            body(&[
                &[0x8b, 0x97, 0x50, 0x49, 0x00, 0x00],
                &[0x8b, 0x8f, 0x64, 0x49, 0x00, 0x00],
                NODE_STRIDE,
                TICKET_PAYLOAD,
            ])
        }

        #[test]
        fn request_enc_accepts_full_shape() {
            let bytes = request_body();
            assert!(validate_request_enc(&bytes, 0));
            let code = code_region(bytes);
            assert_eq!(
                resolve_adapter_implementation(
                    &code,
                    super::super::super::eticket::REQUEST_ENCRYPTED_NAME,
                    BASE,
                    None,
                ),
                Some(BASE)
            );
        }

        #[test]
        fn request_enc_rejects_missing_owner_link() {
            let bytes = body(&[
                ALLOC_JOB,
                ADJUST_THIS,
                JOB_MESSAGE_ZERO,
                EMSG_ETICKET_REQUEST,
                CM_BUILDER_CALL,
            ]);
            assert!(!validate_request_enc(&bytes, 0));
        }

        #[test]
        fn request_enc_rejects_anchors_after_return() {
            let bytes = body(&[
                ALLOC_JOB,
                ADJUST_THIS,
                &[0xc3],
                JOB_MESSAGE_ZERO,
                JOB_OWNER,
                EMSG_ETICKET_REQUEST,
                CM_BUILDER_CALL,
            ]);
            assert!(!validate_request_enc(&bytes, 0));
        }

        #[test]
        fn get_enc_accepts_public_and_publicbeta_offsets() {
            let public = public_get_body();
            let publicbeta = body(&[
                &[0x8b, 0x97, 0x14, 0x48, 0x00, 0x00],
                &[0x8b, 0x8f, 0x28, 0x48, 0x00, 0x00],
                NODE_STRIDE,
                TICKET_PAYLOAD,
            ]);
            assert!(validate_get_enc(&public, 0));
            assert!(validate_get_enc(&publicbeta, 0));
        }

        #[test]
        fn get_enc_rejects_cross_build_offset_pair() {
            let mixed = body(&[
                &[0x8b, 0x97, 0x50, 0x49, 0x00, 0x00],
                &[0x8b, 0x8f, 0x28, 0x48, 0x00, 0x00],
                NODE_STRIDE,
                TICKET_PAYLOAD,
            ]);
            assert!(!validate_get_enc(&mixed, 0));
        }

        #[test]
        fn get_enc_rejects_missing_stride() {
            let bytes = body(&[
                &[0x8b, 0x97, 0x50, 0x49, 0x00, 0x00],
                &[0x8b, 0x8f, 0x64, 0x49, 0x00, 0x00],
                TICKET_PAYLOAD,
            ]);
            assert!(!validate_get_enc(&bytes, 0));
        }

        #[test]
        fn get_enc_rejects_reordered_map_operations() {
            let bytes = body(&[
                NODE_STRIDE,
                &[0x8b, 0x97, 0x50, 0x49, 0x00, 0x00],
                &[0x8b, 0x8f, 0x64, 0x49, 0x00, 0x00],
                TICKET_PAYLOAD,
            ]);
            assert!(!validate_get_enc(&bytes, 0));
        }

        #[test]
        fn get_resolver_accepts_only_adjusting_tail_thunk() {
            let implementation = public_get_body();
            let code = get_thunk_region(GET_THUNK_ADJUST, &implementation);
            assert_eq!(
                resolve_adapter_implementation(
                    &code,
                    super::super::super::eticket::GET_ENCRYPTED_NAME,
                    BASE,
                    None,
                ),
                Some(BASE + IMPL_OFFSET)
            );
            assert_eq!(
                resolve_adapter_implementation(
                    &code,
                    super::super::super::eticket::GET_ENCRYPTED_NAME,
                    BASE + 0x20,
                    None,
                ),
                Some(BASE + IMPL_OFFSET)
            );

            let call = call_region(&implementation);
            assert_eq!(
                resolve_adapter_implementation(
                    &call,
                    super::super::super::eticket::GET_ENCRYPTED_NAME,
                    BASE,
                    None,
                ),
                None
            );
        }
    }
}
