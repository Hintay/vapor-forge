use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRange {
    pub start: usize,
    pub end: usize,
}

impl AddressRange {
    pub const fn contains(self, address: usize) -> bool {
        self.start <= address && address < self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HookTargetInput {
    pub target_address: usize,
    pub replacement_address: usize,
    pub executable_range: AddressRange,
}

/// Opaque proof that a hook target passed the engine's address checks.
///
/// The fields are private so the value can only be produced by
/// [`validate_hook_target`]. Installation APIs consume it and re-check any
/// mutable native state immediately before writing.
#[derive(Debug)]
pub struct ValidatedHookTarget {
    pub(crate) target_address: usize,
    pub(crate) replacement_address: usize,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HookPlanError {
    #[error("hook executable range is empty or reversed")]
    InvalidExecutableRange,
    #[error("hook target address is null")]
    NullTargetAddress,
    #[error("hook replacement address is null")]
    NullReplacementAddress,
    #[error("hook target address is outside the executable range")]
    TargetOutsideExecutableRange,
}

pub type Result<T> = core::result::Result<T, HookPlanError>;

pub fn validate_hook_target(input: HookTargetInput) -> Result<ValidatedHookTarget> {
    if input.executable_range.start >= input.executable_range.end {
        return Err(HookPlanError::InvalidExecutableRange);
    }
    if input.target_address == 0 {
        return Err(HookPlanError::NullTargetAddress);
    }
    if input.replacement_address == 0 {
        return Err(HookPlanError::NullReplacementAddress);
    }
    if !input.executable_range.contains(input.target_address) {
        return Err(HookPlanError::TargetOutsideExecutableRange);
    }
    Ok(ValidatedHookTarget {
        target_address: input.target_address,
        replacement_address: input.replacement_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> HookTargetInput {
        HookTargetInput {
            target_address: 0x1100,
            replacement_address: 0x2000,
            executable_range: AddressRange {
                start: 0x1000,
                end: 0x1800,
            },
        }
    }

    #[test]
    fn validates_target_inside_executable_range() {
        let target = validate_hook_target(valid_input()).unwrap();
        assert_eq!(target.target_address, 0x1100);
        assert_eq!(target.replacement_address, 0x2000);
    }

    #[test]
    fn rejects_invalid_addresses_and_ranges() {
        let mut input = valid_input();
        input.executable_range.end = input.executable_range.start;
        assert_eq!(
            validate_hook_target(input).unwrap_err(),
            HookPlanError::InvalidExecutableRange
        );

        let mut input = valid_input();
        input.target_address = 0;
        assert_eq!(
            validate_hook_target(input).unwrap_err(),
            HookPlanError::NullTargetAddress
        );

        let mut input = valid_input();
        input.replacement_address = 0;
        assert_eq!(
            validate_hook_target(input).unwrap_err(),
            HookPlanError::NullReplacementAddress
        );

        let mut input = valid_input();
        input.target_address = input.executable_range.end;
        assert_eq!(
            validate_hook_target(input).unwrap_err(),
            HookPlanError::TargetOutsideExecutableRange
        );
    }
}
