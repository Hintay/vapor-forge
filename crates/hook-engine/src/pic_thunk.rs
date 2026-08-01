#![allow(clippy::manual_range_contains)]

use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PicThunkError {
    #[error("no PIC thunk call found in the scanned region")]
    NoPicThunkFound,
    #[error("PIC thunk uses an unsupported register (reg_field={0})")]
    UnsupportedThunkRegister(u8),
    #[cfg(test)]
    #[error("PIC thunk repair range is outside the target buffer")]
    PatchOutsideBuffer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThunkRegister {
    Eax,
    Ecx,
    Edx,
    Ebx,
    Esi,
    Edi,
}

impl ThunkRegister {
    fn from_modrm_reg_field(field: u8) -> Result<Self, PicThunkError> {
        match field {
            0 => Ok(Self::Eax),
            1 => Ok(Self::Ecx),
            2 => Ok(Self::Edx),
            3 => Ok(Self::Ebx),
            6 => Ok(Self::Esi),
            7 => Ok(Self::Edi),
            _ => Err(PicThunkError::UnsupportedThunkRegister(field)),
        }
    }

    fn mov_opcode(self) -> u8 {
        0xB8 + match self {
            Self::Eax => 0,
            Self::Ecx => 1,
            Self::Edx => 2,
            Self::Ebx => 3,
            Self::Esi => 6,
            Self::Edi => 7,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PicThunkCallSite {
    pub offset_in_buffer: usize,
    pub call_target: u32,
    pub register: ThunkRegister,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PicThunkRepairPlan {
    pub call_site: PicThunkCallSite,
    pub correct_return_address: u32,
    pub patch_bytes: [u8; 5],
}

/// Scan a byte buffer for a `call rel32` whose target is a PIC thunk
/// (`mov reg,[esp]; ret`), returning the first match.
///
/// This is a pure analysis function. It does not modify any memory.
pub fn find_pic_thunk_call(
    buffer: &[u8],
    buffer_base_address: u32,
    read_target_bytes: &dyn Fn(u32) -> Option<[u8; 4]>,
) -> Result<PicThunkCallSite, PicThunkError> {
    let mut decoder = iced_x86::Decoder::with_ip(
        32,
        buffer,
        u64::from(buffer_base_address),
        iced_x86::DecoderOptions::NONE,
    );

    while decoder.can_decode() {
        let instr = decoder.decode();
        if instr.is_invalid() {
            break;
        }

        if instr.mnemonic() == iced_x86::Mnemonic::Call
            && instr.op0_kind() == iced_x86::OpKind::NearBranch32
        {
            let call_target = instr.near_branch32();
            let offset = (instr.ip() as u32 - buffer_base_address) as usize;

            if let Some(target_bytes) = read_target_bytes(call_target) {
                if is_pic_thunk_bytes(&target_bytes) {
                    let reg_field = (target_bytes[1] >> 3) & 0x7;
                    let register = ThunkRegister::from_modrm_reg_field(reg_field)?;
                    return Ok(PicThunkCallSite {
                        offset_in_buffer: offset,
                        call_target,
                        register,
                    });
                }
            }
        }
    }

    Err(PicThunkError::NoPicThunkFound)
}

/// Build a repair plan: what bytes to write at the call site to replace
/// `call thunk` with `mov reg, <correct_return_address>`.
///
/// `original_call_address` is the address of the `call __x86.get_pc_thunk.*`
/// instruction in the **original function** (before hooking). The correct return
/// address is `original_call_address + 5`.
pub fn plan_pic_thunk_repair(
    call_site: PicThunkCallSite,
    original_call_address: u32,
) -> PicThunkRepairPlan {
    let correct_return_address = original_call_address.wrapping_add(5);
    let imm = correct_return_address.to_le_bytes();
    let patch_bytes = [
        call_site.register.mov_opcode(),
        imm[0],
        imm[1],
        imm[2],
        imm[3],
    ];

    PicThunkRepairPlan {
        call_site,
        correct_return_address,
        patch_bytes,
    }
}

/// Apply a repair plan to a mutable byte buffer (e.g. a test-owned buffer or
/// a trampoline made writable by the caller).
///
/// Returns `Ok(())` if the 5-byte patch was written at the call site offset.
#[cfg(test)]
fn apply_repair_to_buffer(
    buffer: &mut [u8],
    plan: &PicThunkRepairPlan,
) -> Result<(), PicThunkError> {
    let offset = plan.call_site.offset_in_buffer;
    let end = offset
        .checked_add(plan.patch_bytes.len())
        .ok_or(PicThunkError::PatchOutsideBuffer)?;
    let target = buffer
        .get_mut(offset..end)
        .ok_or(PicThunkError::PatchOutsideBuffer)?;
    target.copy_from_slice(&plan.patch_bytes);
    Ok(())
}

fn is_pic_thunk_bytes(bytes: &[u8; 4]) -> bool {
    // mov reg,[esp] = 8b XX 24 where XX has modrm [esp] encoding (mod=00, rm=100)
    // followed by ret = c3
    bytes[0] == 0x8b && bytes[2] == 0x24 && bytes[3] == 0xc3 && (bytes[1] & 0xC7) == 0x04
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_thunk_bytes(reg: ThunkRegister) -> [u8; 4] {
        let modrm = 0x04
            | (match reg {
                ThunkRegister::Eax => 0,
                ThunkRegister::Ecx => 1,
                ThunkRegister::Edx => 2,
                ThunkRegister::Ebx => 3,
                ThunkRegister::Esi => 6,
                ThunkRegister::Edi => 7,
            } << 3);
        [0x8b, modrm, 0x24, 0xc3]
    }

    #[test]
    fn detects_pic_thunk_bytes_for_all_registers() {
        for reg in [
            ThunkRegister::Eax,
            ThunkRegister::Ecx,
            ThunkRegister::Edx,
            ThunkRegister::Ebx,
            ThunkRegister::Esi,
            ThunkRegister::Edi,
        ] {
            assert!(
                is_pic_thunk_bytes(&make_thunk_bytes(reg)),
                "should detect thunk for {:?}",
                reg
            );
        }
    }

    #[test]
    fn rejects_non_thunk_bytes() {
        assert!(!is_pic_thunk_bytes(&[0x8b, 0x04, 0x24, 0x90])); // no ret
        assert!(!is_pic_thunk_bytes(&[0x89, 0x04, 0x24, 0xc3])); // wrong opcode
        assert!(!is_pic_thunk_bytes(&[0x8b, 0x44, 0x24, 0xc3])); // [esp+disp8], not [esp]
    }

    #[test]
    fn finds_pic_thunk_call_in_buffer() {
        // Simulate: call rel32 at offset 0, target = base + 10
        // Buffer base = 0x1000, call target = 0x100A
        let mut buffer = [0x90u8; 16];
        buffer[0] = 0xE8; // call rel32
        let disp: i32 = 5; // target = 0x1000 + 5 + 5 = 0x100A
        buffer[1..5].copy_from_slice(&disp.to_le_bytes());

        let thunk_bytes = make_thunk_bytes(ThunkRegister::Ebx);

        let result = find_pic_thunk_call(&buffer, 0x1000, &|addr| {
            if addr == 0x100A {
                Some(thunk_bytes)
            } else {
                None
            }
        });

        let site = result.expect("should find PIC thunk call");
        assert_eq!(site.offset_in_buffer, 0);
        assert_eq!(site.call_target, 0x100A);
        assert_eq!(site.register, ThunkRegister::Ebx);
    }

    #[test]
    fn reports_no_thunk_in_empty_buffer() {
        let buffer = [0x90u8; 8];
        let result = find_pic_thunk_call(&buffer, 0x1000, &|_| None);
        assert_eq!(result, Err(PicThunkError::NoPicThunkFound));
    }

    #[test]
    fn plans_correct_repair_bytes() {
        let site = PicThunkCallSite {
            offset_in_buffer: 0,
            call_target: 0xDEAD,
            register: ThunkRegister::Eax,
        };
        let plan = plan_pic_thunk_repair(site, 0x1000);

        assert_eq!(plan.correct_return_address, 0x1005);
        // mov eax, 0x00001005 = B8 05 10 00 00
        assert_eq!(plan.patch_bytes, [0xB8, 0x05, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn plans_correct_repair_for_ebx() {
        let site = PicThunkCallSite {
            offset_in_buffer: 3,
            call_target: 0xBEEF,
            register: ThunkRegister::Ebx,
        };
        let plan = plan_pic_thunk_repair(site, 0xABC0);

        assert_eq!(plan.correct_return_address, 0xABC5);
        // mov ebx, 0x0000ABC5 = BB C5 AB 00 00
        assert_eq!(plan.patch_bytes, [0xBB, 0xC5, 0xAB, 0x00, 0x00]);
    }

    #[test]
    fn applies_repair_to_buffer() {
        let mut buffer = [0xE8, 0x05, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90];
        let site = PicThunkCallSite {
            offset_in_buffer: 0,
            call_target: 0xBEEF,
            register: ThunkRegister::Eax,
        };
        let plan = plan_pic_thunk_repair(site, 0x1000);
        apply_repair_to_buffer(&mut buffer, &plan).expect("apply should succeed");

        assert_eq!(buffer[0], 0xB8); // mov eax, imm32
        assert_eq!(&buffer[1..5], &0x1005u32.to_le_bytes());
        assert_eq!(&buffer[5..], &[0x90, 0x90, 0x90]); // untouched
    }

    #[test]
    fn rejects_repair_outside_buffer() {
        let mut buffer = [0x90; 8];
        let plan = plan_pic_thunk_repair(
            PicThunkCallSite {
                offset_in_buffer: 4,
                call_target: 0xBEEF,
                register: ThunkRegister::Eax,
            },
            0x1000,
        );

        assert_eq!(
            apply_repair_to_buffer(&mut buffer, &plan),
            Err(PicThunkError::PatchOutsideBuffer)
        );
    }

    #[test]
    fn end_to_end_find_plan_apply() {
        // Simulate a copied prologue with a thunk call
        let mut buffer = [0x90u8; 16];
        buffer[0] = 0xE8;
        let disp: i32 = 5;
        buffer[1..5].copy_from_slice(&disp.to_le_bytes());

        let thunk_bytes = make_thunk_bytes(ThunkRegister::Eax);
        let base_addr = 0x2000u32;
        let original_fn_addr = 0x1000u32;

        let site = find_pic_thunk_call(&buffer, base_addr, &|addr| {
            if addr == base_addr + 10 {
                Some(thunk_bytes)
            } else {
                None
            }
        })
        .expect("should find thunk");

        let plan = plan_pic_thunk_repair(site, original_fn_addr);
        apply_repair_to_buffer(&mut buffer, &plan).expect("apply should succeed");

        // Verify: buffer[0..5] is now mov eax, 0x1005
        assert_eq!(buffer[0], 0xB8);
        assert_eq!(&buffer[1..5], &0x1005u32.to_le_bytes());
    }
}
