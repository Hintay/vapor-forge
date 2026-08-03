#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetApiCallResultEvidence {
    pub api_call_argument: bool,
    pub api_result_map: bool,
    pub result_record_stride: bool,
    pub target_pipe_argument: bool,
    pub payload_arguments: bool,
    pub result_callback_argument: bool,
    pub completion_callback: bool,
}

impl SetApiCallResultEvidence {
    pub fn is_complete(self) -> bool {
        self.api_call_argument
            && self.api_result_map
            && self.result_record_stride
            && self.target_pipe_argument
            && self.payload_arguments
            && self.result_callback_argument
            && self.completion_callback
    }
}

pub fn set_api_call_result_evidence(
    code: &[u8],
    offset: usize,
    pointer_width: usize,
) -> Option<SetApiCallResultEvidence> {
    match pointer_width {
        4 => set_api_call_result32_evidence(code, offset),
        8 => set_api_call_result64_evidence(code, offset),
        _ => None,
    }
}

fn set_api_call_result32_evidence(code: &[u8], offset: usize) -> Option<SetApiCallResultEvidence> {
    let bytes = bounded_tail(code, offset, 0xa00)?;
    let frame_handle = has_seq(bytes, &[0x8b, 0x45, 0x10]) && has_seq(bytes, &[0x8b, 0x55, 0x14]);
    let stack_handle =
        has_seq(bytes, &[0x8b, 0x44, 0x24, 0x60]) && has_seq(bytes, &[0x8b, 0x44, 0x24, 0x64]);

    Some(SetApiCallResultEvidence {
        api_call_argument: frame_handle
            || stack_handle
            || has_seq(bytes, &[0xf3, 0x0f, 0x7e, 0x45, 0x10]),
        api_result_map: (has_x86_rm32_disp32_load(bytes, 0x14ac)
            && has_x86_rm32_disp32_load(bytes, 0x14c0))
            || (has_seq(bytes, &[0x05, 0x98, 0x14, 0x00, 0x00])
                && has_x86_rm32_disp32_operand(bytes, 0x14c0)),
        result_record_stride: (has_seq(bytes, &[0x8d, 0x0c, 0x7f])
            && has_seq(bytes, &[0xc1, 0xe1, 0x04]))
            || (has_seq(bytes, &[0x8d, 0x34, 0x40]) && has_seq(bytes, &[0xc1, 0xe6, 0x04])),
        target_pipe_argument: has_seq(bytes, &[0x8b, 0x55, 0x18])
            || has_seq(bytes, &[0x8b, 0x7d, 0x18])
            || has_seq(bytes, &[0x83, 0x7d, 0x18, 0x00])
            || has_seq(bytes, &[0x8b, 0x54, 0x24, 0x60]),
        payload_arguments: (has_seq(bytes, &[0x8b, 0x45, 0x1c])
            && (has_seq(bytes, &[0x8b, 0x45, 0x20]) || has_seq(bytes, &[0x8b, 0x55, 0x20])))
            || (has_seq(bytes, &[0x8b, 0x44, 0x24, 0x64])
                && has_seq(bytes, &[0x8b, 0x44, 0x24, 0x68])),
        result_callback_argument: has_seq(bytes, &[0x8b, 0x45, 0x24])
            || has_seq(bytes, &[0x8b, 0x44, 0x24, 0x6c]),
        completion_callback: has_x86_push_imm32(bytes, 703),
    })
}

fn set_api_call_result64_evidence(code: &[u8], offset: usize) -> Option<SetApiCallResultEvidence> {
    let bytes = bounded_tail(code, offset, 0x780)?;
    let ordinary_current = has_seq(bytes, &[0x48, 0x81, 0xc7, 0xa8, 0x19, 0x00, 0x00])
        && has_seq(bytes, &[0x4d, 0x03, 0xbe, 0xd8, 0x19, 0x00, 0x00]);
    let ordinary_older = has_x64_rm32_disp32_load(bytes, 0x19c0)
        && has_seq(bytes, &[0x48, 0x8b, 0x8f, 0xd8, 0x19, 0x00, 0x00]);
    let steamrt = has_x64_rm32_disp32_load(bytes, 0x19a8)
        && has_seq(bytes, &[0x4d, 0x8b, 0x8d, 0xd8, 0x19, 0x00, 0x00]);

    Some(SetApiCallResultEvidence {
        api_call_argument: has_seq(bytes, &[0x48, 0x89, 0xd5])
            || has_seq(bytes, &[0x49, 0x89, 0xd4])
            || has_seq(bytes, &[0x49, 0x89, 0xd5]),
        api_result_map: ordinary_current || ordinary_older || steamrt,
        result_record_stride: has_seq(bytes, &[0x48, 0x6b, 0xdb, 0x38])
            || has_seq(bytes, &[0x4d, 0x6b, 0xc0, 0x38])
            || has_seq(bytes, &[0x4d, 0x6b, 0xed, 0x38])
            || has_seq(bytes, &[0x4d, 0x6b, 0xff, 0x38]),
        target_pipe_argument: (has_seq(bytes, &[0x41, 0x89, 0xcf])
            && has_seq(bytes, &[0x45, 0x85, 0xff]))
            || (has_seq(bytes, &[0x89, 0xcd]) && has_seq(bytes, &[0x85, 0xed])),
        payload_arguments: (has_seq(bytes, &[0x4d, 0x89, 0xc6])
            && has_seq(bytes, &[0x45, 0x89, 0xca]))
            || (has_seq(bytes, &[0x4d, 0x89, 0xc4]) && has_seq(bytes, &[0x44, 0x89, 0xcb])),
        result_callback_argument: has_x64_stack_dword_load(bytes, 0x70)
            || has_x64_stack_dword_load(bytes, 0xa0),
        completion_callback: has_x64_mov_edx_imm32(bytes, 703),
    })
}

fn bounded_tail(bytes: &[u8], offset: usize, max_len: usize) -> Option<&[u8]> {
    let tail = bytes.get(offset..)?;
    Some(&tail[..tail.len().min(max_len)])
}

fn has_seq(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
}

fn has_x86_rm32_disp32_load(bytes: &[u8], displacement: u32) -> bool {
    let displacement = displacement.to_le_bytes();
    bytes.windows(6).any(|window| {
        window[0] == 0x8b && matches!(window[1], 0x80..=0xbf) && window[2..6] == displacement
    })
}

fn has_x86_rm32_disp32_operand(bytes: &[u8], displacement: u32) -> bool {
    let displacement = displacement.to_le_bytes();
    bytes.windows(6).any(|window| {
        matches!(window[0], 0x03 | 0x8b | 0x8d)
            && matches!(window[1], 0x80..=0xbf)
            && window[2..6] == displacement
    })
}

fn has_x64_rm32_disp32_load(bytes: &[u8], displacement: u32) -> bool {
    let displacement = displacement.to_le_bytes();
    bytes.windows(6).any(|window| {
        window[0] == 0x8b && matches!(window[1], 0x80..=0xbf) && window[2..6] == displacement
    }) || bytes.windows(7).any(|window| {
        window[0] == 0x44
            && window[1] == 0x8b
            && matches!(window[2], 0x80..=0xbf)
            && window[3..7] == displacement
    })
}

fn has_x86_push_imm32(bytes: &[u8], value: u32) -> bool {
    let value = value.to_le_bytes();
    bytes
        .windows(5)
        .any(|window| window[0] == 0x68 && window[1..5] == value)
}

fn has_x64_mov_edx_imm32(bytes: &[u8], value: u32) -> bool {
    let value = value.to_le_bytes();
    bytes
        .windows(5)
        .any(|window| window[0] == 0xba && window[1..5] == value)
}

fn has_x64_stack_dword_load(bytes: &[u8], displacement: u8) -> bool {
    bytes.windows(4).any(|window| {
        window[0] == 0x8b
            && (window[1] & 0xc7) == 0x44
            && window[2] == 0x24
            && window[3] == displacement
    }) || bytes.windows(7).any(|window| {
        window[0] == 0x8b
            && (window[1] & 0xc7) == 0x84
            && window[2] == 0x24
            && window[3..7] == u32::from(displacement).to_le_bytes()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unrelated_code() {
        let code = [0x90; 64];
        assert!(!set_api_call_result_evidence(&code, 0, 4)
            .unwrap()
            .is_complete());
        assert!(!set_api_call_result_evidence(&code, 0, 8)
            .unwrap()
            .is_complete());
    }
}
