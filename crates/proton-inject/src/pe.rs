// PE export table parser. Operates on &[u8] read from disk. Safe code only.

const PE_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
const EXPORT_DIR_INDEX: usize = 0;

pub fn find_export_rva(pe_bytes: &[u8], name: &str) -> Option<u32> {
    let dos_e_lfanew = read_u32(pe_bytes, 0x3C)? as usize;
    let pe_sig = read_u32(pe_bytes, dos_e_lfanew)?;
    if pe_sig != PE_SIGNATURE {
        return None;
    }

    // COFF header starts after PE signature (4 bytes)
    let coff_start = dos_e_lfanew + 4;
    let optional_hdr_size = read_u16(pe_bytes, coff_start + 16)? as usize;

    // Optional header starts after COFF header (20 bytes)
    let opt_start = coff_start + 20;
    let magic = read_u16(pe_bytes, opt_start)?;

    // Data directory offset depends on PE32 vs PE32+
    let dd_offset = match magic {
        0x10B => opt_start + 96,  // PE32: 96 bytes to data directories
        0x20B => opt_start + 112, // PE32+ (64-bit): 112 bytes
        _ => return None,
    };

    if dd_offset + 8 > opt_start + optional_hdr_size {
        return None;
    }

    // Export directory is data directory entry 0
    let export_rva = read_u32(pe_bytes, dd_offset + EXPORT_DIR_INDEX * 8)?;
    let export_size = read_u32(pe_bytes, dd_offset + EXPORT_DIR_INDEX * 8 + 4)?;
    if export_rva == 0 || export_size == 0 {
        return None;
    }

    // Convert RVA to file offset using section headers
    let num_sections = read_u16(pe_bytes, coff_start + 2)? as usize;
    let sections_start = opt_start + optional_hdr_size;

    let export_file_offset = rva_to_offset(pe_bytes, sections_start, num_sections, export_rva)?;

    // Parse export directory
    let dir = export_file_offset as usize;
    let num_names = read_u32(pe_bytes, dir + 24)? as usize;
    let names_rva = read_u32(pe_bytes, dir + 32)?;
    let ordinals_rva = read_u32(pe_bytes, dir + 36)?;
    let functions_rva = read_u32(pe_bytes, dir + 28)?;

    let names_off = rva_to_offset(pe_bytes, sections_start, num_sections, names_rva)? as usize;
    let ordinals_off =
        rva_to_offset(pe_bytes, sections_start, num_sections, ordinals_rva)? as usize;
    let functions_off =
        rva_to_offset(pe_bytes, sections_start, num_sections, functions_rva)? as usize;

    for i in 0..num_names {
        let name_rva = read_u32(pe_bytes, names_off + i * 4)?;
        let name_off = rva_to_offset(pe_bytes, sections_start, num_sections, name_rva)? as usize;

        if read_cstring(pe_bytes, name_off) == name {
            let ordinal = read_u16(pe_bytes, ordinals_off + i * 2)? as usize;
            let func_rva = read_u32(pe_bytes, functions_off + ordinal * 4)?;
            return Some(func_rva);
        }
    }

    None
}

fn rva_to_offset(
    pe_bytes: &[u8],
    sections_start: usize,
    num_sections: usize,
    rva: u32,
) -> Option<u32> {
    for i in 0..num_sections {
        let sec = sections_start + i * 40;
        let virt_addr = read_u32(pe_bytes, sec + 12)?;
        let virt_size = read_u32(pe_bytes, sec + 8)?;
        let raw_offset = read_u32(pe_bytes, sec + 20)?;

        if rva >= virt_addr && rva < virt_addr + virt_size {
            return Some(raw_offset + (rva - virt_addr));
        }
    }
    None
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_cstring(data: &[u8], offset: usize) -> String {
    let mut s = String::new();
    let mut i = offset;
    while i < data.len() {
        let b = data[i];
        if b == 0 {
            break;
        }
        s.push(b as char);
        i += 1;
    }
    s
}

// -----------------------------------------------------------------------
// PE section header scanning (for Denuvo detection)
// -----------------------------------------------------------------------

const SECTION_NAME_LEN: usize = 8;

/// Extract all section names from a PE file on disk.
pub fn section_names(pe_bytes: &[u8]) -> Vec<String> {
    let Some(dos_e_lfanew) = read_u32(pe_bytes, 0x3C) else {
        return Vec::new();
    };
    let dos_e_lfanew = dos_e_lfanew as usize;
    if read_u32(pe_bytes, dos_e_lfanew) != Some(PE_SIGNATURE) {
        return Vec::new();
    }
    let coff_start = dos_e_lfanew + 4;
    let num_sections = match read_u16(pe_bytes, coff_start + 2) {
        Some(n) => n as usize,
        None => return Vec::new(),
    };
    let optional_hdr_size = match read_u16(pe_bytes, coff_start + 16) {
        Some(n) => n as usize,
        None => return Vec::new(),
    };
    let sections_start = coff_start + 20 + optional_hdr_size;

    let mut names = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let offset = sections_start + i * 40;
        if offset + SECTION_NAME_LEN > pe_bytes.len() {
            break;
        }
        let raw = &pe_bytes[offset..offset + SECTION_NAME_LEN];
        let name = read_section_name(raw);
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

fn read_section_name(raw: &[u8]) -> String {
    let mut s = String::new();
    for &b in raw {
        if b == 0 {
            break;
        }
        s.push(b as char);
    }
    s
}

/// Known PE section names associated with Denuvo/Themida DRM.
pub const DENUVO_SECTIONS: &[&str] = &[".arch", ".srdata", ".themida"];

/// Known DLL base names associated with Denuvo.
const DENUVO_DLL_NAMES: &[&str] = &["denuvo"];

/// Check if a UTF-16LE DLL name (from LdrLoadDll) looks like a Denuvo component.
pub fn is_denuvo_dll_name(name: &[u16]) -> bool {
    let lower: Vec<u16> = name
        .iter()
        .map(|&c| {
            if (0x41..=0x5A).contains(&c) {
                c + 32
            } else {
                c
            }
        })
        .collect();

    for pattern in DENUVO_DLL_NAMES {
        let pat_u16: Vec<u16> = pattern.bytes().map(|b| b as u16).collect();
        if lower
            .windows(pat_u16.len())
            .any(|window| window == pat_u16.as_slice())
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_helpers() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u16(&data, 0), Some(0x0201));
        assert_eq!(read_u32(&data, 0), Some(0x04030201));
        assert_eq!(read_u16(&data, 3), None);
    }

    #[test]
    fn section_names_empty_on_non_pe() {
        assert!(section_names(&[0u8; 64]).is_empty());
    }

    #[test]
    fn denuvo_dll_name_detection() {
        let name: Vec<u16> = "Denuvo64.dll".encode_utf16().collect();
        assert!(is_denuvo_dll_name(&name));

        let name: Vec<u16> = "kernel32.dll".encode_utf16().collect();
        assert!(!is_denuvo_dll_name(&name));
    }
}
