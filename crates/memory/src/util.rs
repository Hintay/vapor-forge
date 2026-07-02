pub(crate) fn truncate_str(value: &str, max_len: usize) -> String {
    value.chars().take(max_len).collect()
}

pub(crate) fn looks_like_mangled_cpp_symbol(symbol: &str) -> bool {
    symbol.starts_with("_Z")
}

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

pub(crate) fn fnv1a64_digest(bytes: &[u8]) -> String {
    let mut value = 0xcbf29ce484222325u64;
    for byte in bytes {
        value ^= u64::from(*byte);
        value = value.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{value:016x}")
}
