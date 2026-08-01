pub(crate) fn retry_delay(attempts: i64) -> i64 {
    1_i64 << attempts.clamp(0, 8) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_is_exponential_and_capped() {
        assert_eq!(retry_delay(0), 1);
        assert_eq!(retry_delay(4), 16);
        assert_eq!(retry_delay(8), 256);
        assert_eq!(retry_delay(100), 256);
        assert_eq!(retry_delay(-1), 1);
    }
}
