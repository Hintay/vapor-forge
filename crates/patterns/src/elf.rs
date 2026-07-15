const PT_LOAD: u32 = 1;
const PF_X: u32 = 0x1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

impl ElfClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Elf32 => "ELF32",
            Self::Elf64 => "ELF64",
        }
    }

    pub fn word_size(self) -> usize {
        match self {
            Self::Elf32 => 4,
            Self::Elf64 => 8,
        }
    }

    pub fn bits(self) -> u8 {
        self.word_size() as u8 * 8
    }
}

#[derive(Clone, Copy)]
pub struct LoadSegment {
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

impl LoadSegment {
    pub fn is_executable(self) -> bool {
        self.flags & PF_X != 0
    }
}

pub struct ElfImage<'a> {
    data: &'a [u8],
    pub class: ElfClass,
    pub loads: Vec<LoadSegment>,
}

impl<'a> ElfImage<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.get(..4) != Some(b"\x7fELF") {
            return Err("input is not an ELF file".to_owned());
        }
        if data.get(5) != Some(&1) {
            return Err("big-endian ELF files are not supported".to_owned());
        }

        let class = match data.get(4) {
            Some(1) => ElfClass::Elf32,
            Some(2) => ElfClass::Elf64,
            _ => return Err("unsupported ELF class".to_owned()),
        };
        let loads = match class {
            ElfClass::Elf32 => parse_loads_elf32(data)?,
            ElfClass::Elf64 => parse_loads_elf64(data)?,
        };
        if loads.is_empty() {
            return Err("ELF file has no PT_LOAD segments".to_owned());
        }
        Ok(Self { data, class, loads })
    }

    pub fn word_size(&self) -> usize {
        self.class.word_size()
    }

    pub fn va_to_offset(&self, va: u64) -> Option<usize> {
        self.loads.iter().find_map(|load| {
            let end = load.vaddr.checked_add(load.filesz)?;
            (va >= load.vaddr && va < end).then(|| (load.offset + (va - load.vaddr)) as usize)
        })
    }

    pub fn in_text(&self, va: u64) -> bool {
        self.loads.iter().any(|load| {
            load.is_executable() && va >= load.vaddr && va < load.vaddr.saturating_add(load.filesz)
        })
    }

    pub fn in_module(&self, va: u64) -> bool {
        self.loads
            .iter()
            .any(|load| va >= load.vaddr && va < load.vaddr.saturating_add(load.memsz))
    }

    pub fn read_word_va(&self, va: u64) -> Option<u64> {
        let offset = self.va_to_offset(va)?;
        match self.class {
            ElfClass::Elf32 => read_u32(self.data, offset).ok().map(u64::from),
            ElfClass::Elf64 => read_u64(self.data, offset).ok(),
        }
    }

    pub fn read_u32_va(&self, va: u64) -> Option<u32> {
        read_u32(self.data, self.va_to_offset(va)?).ok()
    }

    pub fn read_i32_va(&self, va: u64) -> Option<i32> {
        let offset = self.va_to_offset(va)?;
        let bytes = self.data.get(offset..offset + 4)?;
        Some(i32::from_le_bytes(bytes.try_into().ok()?))
    }

    pub fn read_u8_va(&self, va: u64) -> Option<u8> {
        self.data.get(self.va_to_offset(va)?).copied()
    }

    pub fn read_cstring(&self, va: u64, max_len: usize) -> String {
        let Some(offset) = self.va_to_offset(va) else {
            return String::new();
        };
        let mut out = String::new();
        for &byte in self.data[offset..].iter().take(max_len) {
            if byte == 0 {
                return out;
            }
            if !(0x20..=0x7e).contains(&byte) {
                return String::new();
            }
            out.push(byte as char);
        }
        String::new()
    }

    pub fn largest_executable_segment(&self) -> Result<ExecutableSegment<'a>, String> {
        let load = self
            .loads
            .iter()
            .filter(|load| load.is_executable())
            .max_by_key(|load| load.filesz)
            .ok_or_else(|| "ELF file has no executable PT_LOAD segment".to_owned())?;
        let start = load.offset as usize;
        let end = start
            .checked_add(load.filesz as usize)
            .ok_or_else(|| "executable segment range overflows usize".to_owned())?;
        let bytes = self
            .data
            .get(start..end)
            .ok_or_else(|| "executable segment extends past EOF".to_owned())?;
        Ok(ExecutableSegment {
            bytes,
            file_offset: load.offset,
            vaddr: load.vaddr,
            elf_class: self.class,
        })
    }
}

pub struct ExecutableSegment<'a> {
    pub bytes: &'a [u8],
    pub file_offset: u64,
    pub vaddr: u64,
    pub elf_class: ElfClass,
}

fn parse_loads_elf32(data: &[u8]) -> Result<Vec<LoadSegment>, String> {
    let phoff = read_u32(data, 28)? as usize;
    let phentsize = read_u16(data, 42)? as usize;
    let phnum = read_u16(data, 44)? as usize;
    let mut loads = Vec::new();
    for idx in 0..phnum {
        let off = phoff + idx * phentsize;
        if read_u32(data, off)? == PT_LOAD {
            loads.push(LoadSegment {
                offset: read_u32(data, off + 4)? as u64,
                vaddr: read_u32(data, off + 8)? as u64,
                filesz: read_u32(data, off + 16)? as u64,
                memsz: read_u32(data, off + 20)? as u64,
                flags: read_u32(data, off + 24)?,
            });
        }
    }
    Ok(loads)
}

fn parse_loads_elf64(data: &[u8]) -> Result<Vec<LoadSegment>, String> {
    let phoff = read_u64(data, 32)? as usize;
    let phentsize = read_u16(data, 54)? as usize;
    let phnum = read_u16(data, 56)? as usize;
    let mut loads = Vec::new();
    for idx in 0..phnum {
        let off = phoff + idx * phentsize;
        if read_u32(data, off)? == PT_LOAD {
            loads.push(LoadSegment {
                flags: read_u32(data, off + 4)?,
                offset: read_u64(data, off + 8)?,
                vaddr: read_u64(data, off + 16)?,
                filesz: read_u64(data, off + 32)?,
                memsz: read_u64(data, off + 40)?,
            });
        }
    }
    Ok(loads)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| "ELF header is truncated".to_owned())?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| "ELF header is truncated".to_owned())?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| "ELF header is truncated".to_owned())?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::ElfImage;

    fn elf64_with_load(flags: u32, file_offset: u64, vaddr: u64, size: u64) -> Vec<u8> {
        let mut data = vec![0u8; (file_offset + size).max(120) as usize];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[32..40].copy_from_slice(&64u64.to_le_bytes());
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&1u16.to_le_bytes());
        data[64..68].copy_from_slice(&1u32.to_le_bytes());
        data[68..72].copy_from_slice(&flags.to_le_bytes());
        data[72..80].copy_from_slice(&file_offset.to_le_bytes());
        data[80..88].copy_from_slice(&vaddr.to_le_bytes());
        data[96..104].copy_from_slice(&size.to_le_bytes());
        data[104..112].copy_from_slice(&size.to_le_bytes());
        data
    }

    #[test]
    fn selects_executable_segment() {
        let data = elf64_with_load(1, 120, 0x1000, 8);
        let image = ElfImage::parse(&data).unwrap();
        let segment = image.largest_executable_segment().unwrap();
        assert_eq!(segment.file_offset, 120);
        assert_eq!(segment.vaddr, 0x1000);
        assert_eq!(segment.bytes.len(), 8);
    }

    #[test]
    fn treats_bss_as_module_memory_but_not_file_data() {
        let mut data = elf64_with_load(0, 120, 0x1000, 8);
        data[104..112].copy_from_slice(&0x20u64.to_le_bytes());
        let image = ElfImage::parse(&data).unwrap();

        assert!(image.in_module(0x1010));
        assert_eq!(image.va_to_offset(0x1010), None);
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(ElfImage::parse(b"\x7fELF\x02\x01").is_err());
    }
}
