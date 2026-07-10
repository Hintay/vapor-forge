#![forbid(unsafe_code)]

#[cfg(test)]
use core::fmt;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookState {
    Empty,
    Planned,
    Installed,
    Invoked,
    Skipped,
    Failed,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum HookBoundaryError {
    #[cfg(test)]
    #[error("hook plan is empty")]
    EmptyPlan,
    #[cfg(test)]
    #[error("hook plan target is missing")]
    MissingTarget,
    #[cfg(test)]
    #[error("hook plan replacement is missing")]
    MissingReplacement,
    #[cfg(test)]
    #[error("hook slot is already installed")]
    AlreadyInstalled,
    #[error("raw hook module name is empty")]
    EmptyModuleName,
    #[error("raw hook module name does not match the expected module")]
    ModuleMismatch,
    #[error("raw hook architecture does not match the expected architecture")]
    UnsupportedArchitecture,
    #[error("raw hook target address is null")]
    NullTargetAddress,
    #[error("raw hook replacement address is null")]
    NullReplacementAddress,
    #[error("raw hook target address is outside the executable range")]
    TargetOutsideExecutableRange,
    #[error("raw hook plan requested a memory write")]
    WritesNotAllowed,
    #[error("raw hook installation is not allowed in the current phase")]
    InstallationNotAllowed,
    #[error("patch plan does not have enough bytes available")]
    PatchLengthTooSmall,
    #[error("patch plan relative jump is outside the supported range")]
    RelativeJumpOutOfRange,
    #[cfg(test)]
    #[error("synthetic patch buffer is too small")]
    SyntheticBufferTooSmall,
    #[cfg(test)]
    #[error("synthetic patch range is outside the buffer")]
    SyntheticPatchOutsideBuffer,
}

pub type Result<T> = core::result::Result<T, HookBoundaryError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawAddressRange {
    pub start: usize,
    pub end: usize,
}

impl RawAddressRange {
    pub const fn contains(&self, address: usize) -> bool {
        self.start <= address && address < self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawHookEligibilityInput<'a> {
    pub module_name: &'a str,
    pub expected_module_name: &'a str,
    pub actual_architecture: &'a str,
    pub expected_architecture: &'a str,
    pub target_address: usize,
    pub replacement_address: usize,
    pub executable_range: RawAddressRange,
    pub write_requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawHookPlanEligibility {
    pub module_name: String,
    pub architecture: String,
    pub target_address: usize,
    pub replacement_address: usize,
    pub state: HookState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawHookRequestedAction {
    ValidateOnly,
    Install,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawHookActionDecision {
    pub action: RawHookRequestedAction,
    pub eligibility: RawHookPlanEligibility,
    pub state: HookState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchEncoding {
    X86RelativeJump32,
}

impl PatchEncoding {
    pub const fn required_len(self) -> usize {
        match self {
            Self::X86RelativeJump32 => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PatchPlanInput<'a> {
    pub raw: RawHookEligibilityInput<'a>,
    pub action: RawHookRequestedAction,
    pub encoding: PatchEncoding,
    pub available_patch_bytes: usize,
    pub minimum_patch_bytes: usize,
    pub memory_write_requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchPlanDecision {
    pub action: RawHookRequestedAction,
    pub module_name: String,
    pub architecture: String,
    pub encoding: PatchEncoding,
    pub required_patch_bytes: usize,
    pub available_patch_bytes: usize,
    pub relative_displacement: i64,
    pub would_require_memory_permission_change: bool,
    pub state: HookState,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticPatchSimulationReport {
    pub patch_offset: usize,
    pub patched_len: usize,
    pub buffer_len: usize,
    pub state: HookState,
}

pub fn validate_raw_hook_plan(
    input: RawHookEligibilityInput<'_>,
) -> Result<RawHookPlanEligibility> {
    if input.module_name.is_empty() || input.expected_module_name.is_empty() {
        return Err(HookBoundaryError::EmptyModuleName);
    }

    if !module_name_matches(input.module_name, input.expected_module_name) {
        return Err(HookBoundaryError::ModuleMismatch);
    }

    if input.actual_architecture != input.expected_architecture {
        return Err(HookBoundaryError::UnsupportedArchitecture);
    }

    if input.target_address == 0 {
        return Err(HookBoundaryError::NullTargetAddress);
    }

    if input.replacement_address == 0 {
        return Err(HookBoundaryError::NullReplacementAddress);
    }

    if !input.executable_range.contains(input.target_address) {
        return Err(HookBoundaryError::TargetOutsideExecutableRange);
    }

    if input.write_requested {
        return Err(HookBoundaryError::WritesNotAllowed);
    }

    Ok(RawHookPlanEligibility {
        module_name: input.expected_module_name.to_owned(),
        architecture: input.expected_architecture.to_owned(),
        target_address: input.target_address,
        replacement_address: input.replacement_address,
        state: HookState::Planned,
    })
}

pub fn evaluate_raw_hook_action(
    input: RawHookEligibilityInput<'_>,
    action: RawHookRequestedAction,
) -> Result<RawHookActionDecision> {
    if action == RawHookRequestedAction::Install {
        return Err(HookBoundaryError::InstallationNotAllowed);
    }

    let eligibility = validate_raw_hook_plan(input)?;

    Ok(RawHookActionDecision {
        action,
        eligibility,
        state: HookState::Planned,
    })
}

pub fn validate_patch_plan(input: PatchPlanInput<'_>) -> Result<PatchPlanDecision> {
    if input.memory_write_requested {
        return Err(HookBoundaryError::WritesNotAllowed);
    }

    let action_decision = evaluate_raw_hook_action(input.raw, input.action)?;
    let required_patch_bytes = input.encoding.required_len().max(input.minimum_patch_bytes);

    if input.available_patch_bytes < required_patch_bytes {
        return Err(HookBoundaryError::PatchLengthTooSmall);
    }

    let relative_displacement = relative_jump32_displacement(
        action_decision.eligibility.target_address,
        action_decision.eligibility.replacement_address,
        input.encoding.required_len(),
    )?;

    Ok(PatchPlanDecision {
        action: action_decision.action,
        module_name: action_decision.eligibility.module_name,
        architecture: action_decision.eligibility.architecture,
        encoding: input.encoding,
        required_patch_bytes,
        available_patch_bytes: input.available_patch_bytes,
        relative_displacement,
        would_require_memory_permission_change: true,
        state: HookState::Planned,
    })
}

#[cfg(test)]
pub fn simulate_synthetic_patch(
    buffer: &mut [u8],
    plan: &PatchPlanDecision,
    patch_offset: usize,
) -> Result<SyntheticPatchSimulationReport> {
    if buffer.len() < plan.required_patch_bytes {
        return Err(HookBoundaryError::SyntheticBufferTooSmall);
    }

    let patch_end = patch_offset
        .checked_add(plan.required_patch_bytes)
        .ok_or(HookBoundaryError::SyntheticPatchOutsideBuffer)?;

    if patch_end > buffer.len() {
        return Err(HookBoundaryError::SyntheticPatchOutsideBuffer);
    }

    buffer[patch_offset..patch_end].fill(SYNTHETIC_PATCH_MARKER);

    Ok(SyntheticPatchSimulationReport {
        patch_offset,
        patched_len: plan.required_patch_bytes,
        buffer_len: buffer.len(),
        state: HookState::Planned,
    })
}

#[cfg(test)]
const SYNTHETIC_PATCH_MARKER: u8 = 0xD5;

fn relative_jump32_displacement(
    target_address: usize,
    replacement_address: usize,
    instruction_len: usize,
) -> Result<i64> {
    let source_after_instruction = (target_address as i128) + (instruction_len as i128);
    let displacement = (replacement_address as i128) - source_after_instruction;

    if displacement < i32::MIN as i128 || displacement > i32::MAX as i128 {
        return Err(HookBoundaryError::RelativeJumpOutOfRange);
    }

    Ok(displacement as i64)
}

fn module_name_matches(module_name: &str, expected_module_name: &str) -> bool {
    module_name == expected_module_name
        || module_name.rsplit('/').next() == Some(expected_module_name)
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub struct SyntheticHookPlan<F>
where
    F: Copy,
{
    target: Option<F>,
    replacement: Option<F>,
    state: HookState,
}

#[cfg(test)]
impl<F> fmt::Debug for SyntheticHookPlan<F>
where
    F: Copy,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticHookPlan")
            .field("has_target", &self.target.is_some())
            .field("has_replacement", &self.replacement.is_some())
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(test)]
impl<F> SyntheticHookPlan<F>
where
    F: Copy,
{
    pub const fn empty() -> Self {
        Self {
            target: None,
            replacement: None,
            state: HookState::Empty,
        }
    }

    pub const fn new(target: F, replacement: F) -> Self {
        Self {
            target: Some(target),
            replacement: Some(replacement),
            state: HookState::Planned,
        }
    }

    pub const fn missing_replacement(target: F) -> Self {
        Self {
            target: Some(target),
            replacement: None,
            state: HookState::Planned,
        }
    }

    pub const fn state(&self) -> HookState {
        self.state
    }

    pub fn validate(&mut self) -> Result<()> {
        match (self.target.is_some(), self.replacement.is_some()) {
            (true, true) => Ok(()),
            (false, false) => {
                self.state = HookState::Failed;
                Err(HookBoundaryError::EmptyPlan)
            }
            (false, true) => {
                self.state = HookState::Failed;
                Err(HookBoundaryError::MissingTarget)
            }
            (true, false) => {
                self.state = HookState::Failed;
                Err(HookBoundaryError::MissingReplacement)
            }
        }
    }

    fn replacement(&mut self) -> Result<F> {
        self.validate()?;
        self.replacement
            .ok_or(HookBoundaryError::MissingReplacement)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub struct SyntheticHookSlot<F>
where
    F: Copy,
{
    current: F,
    state: HookState,
}

#[cfg(test)]
impl<F> SyntheticHookSlot<F>
where
    F: Copy,
{
    pub const fn new(target: F) -> Self {
        Self {
            current: target,
            state: HookState::Empty,
        }
    }

    pub const fn current(&self) -> F {
        self.current
    }

    pub const fn state(&self) -> HookState {
        self.state
    }

    pub fn install(&mut self, plan: &mut SyntheticHookPlan<F>) -> Result<()> {
        if self.state == HookState::Installed || self.state == HookState::Invoked {
            plan.state = HookState::Failed;
            return Err(HookBoundaryError::AlreadyInstalled);
        }

        self.current = plan.replacement()?;
        self.state = HookState::Installed;
        plan.state = HookState::Installed;
        Ok(())
    }

    pub fn mark_invoked(&mut self) {
        if self.state == HookState::Installed {
            self.state = HookState::Invoked;
        }
    }

    pub fn skip(&mut self) {
        if self.state == HookState::Empty {
            self.state = HookState::Skipped;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_raw_hook_action, simulate_synthetic_patch, validate_patch_plan,
        validate_raw_hook_plan, HookBoundaryError, HookState, PatchEncoding, PatchPlanInput,
        RawAddressRange, RawHookEligibilityInput, RawHookRequestedAction, SyntheticHookPlan,
        SyntheticHookSlot,
    };

    type SyntheticFn = extern "C" fn(i32) -> i32;

    extern "C" fn target(value: i32) -> i32 {
        value + 1
    }

    extern "C" fn replacement(value: i32) -> i32 {
        value + 10
    }

    fn valid_raw_input() -> RawHookEligibilityInput<'static> {
        RawHookEligibilityInput {
            module_name: "/tmp/steamui.so",
            expected_module_name: "steamui.so",
            actual_architecture: "x86",
            expected_architecture: "x86",
            target_address: 0x1200,
            replacement_address: 0x2200,
            executable_range: RawAddressRange {
                start: 0x1000,
                end: 0x2000,
            },
            write_requested: false,
        }
    }

    fn valid_patch_plan_input() -> PatchPlanInput<'static> {
        PatchPlanInput {
            raw: valid_raw_input(),
            action: RawHookRequestedAction::ValidateOnly,
            encoding: PatchEncoding::X86RelativeJump32,
            available_patch_bytes: 8,
            minimum_patch_bytes: 5,
            memory_write_requested: false,
        }
    }

    #[test]
    fn empty_slot_calls_original_target() {
        let slot = SyntheticHookSlot::new(target as SyntheticFn);
        let current = slot.current();

        assert_eq!(slot.state(), HookState::Empty);
        assert_eq!(current(5), 6);
    }

    #[test]
    fn installed_plan_calls_replacement() {
        let mut slot = SyntheticHookSlot::new(target as SyntheticFn);
        let mut plan = SyntheticHookPlan::new(target as SyntheticFn, replacement as SyntheticFn);

        slot.install(&mut plan).expect("synthetic install succeeds");
        let current = slot.current();
        assert_eq!(current(5), 15);

        slot.mark_invoked();
        assert_eq!(plan.state(), HookState::Installed);
        assert_eq!(slot.state(), HookState::Invoked);
    }

    #[test]
    fn empty_plan_fails_closed() {
        let mut slot = SyntheticHookSlot::new(target as SyntheticFn);
        let mut plan = SyntheticHookPlan::<SyntheticFn>::empty();

        let error = slot.install(&mut plan).expect_err("empty plan must fail");

        assert_eq!(error, HookBoundaryError::EmptyPlan);
        assert_eq!(plan.state(), HookState::Failed);
        assert_eq!(slot.state(), HookState::Empty);
        assert_eq!(slot.current()(5), 6);
    }

    #[test]
    fn missing_replacement_fails_closed() {
        let mut slot = SyntheticHookSlot::new(target as SyntheticFn);
        let mut plan = SyntheticHookPlan::missing_replacement(target as SyntheticFn);

        let error = slot
            .install(&mut plan)
            .expect_err("missing replacement must fail");

        assert_eq!(error, HookBoundaryError::MissingReplacement);
        assert_eq!(plan.state(), HookState::Failed);
        assert_eq!(slot.current()(5), 6);
    }

    #[test]
    fn double_install_fails_closed() {
        let mut slot = SyntheticHookSlot::new(target as SyntheticFn);
        let mut first = SyntheticHookPlan::new(target as SyntheticFn, replacement as SyntheticFn);
        let mut second = SyntheticHookPlan::new(target as SyntheticFn, replacement as SyntheticFn);

        slot.install(&mut first).expect("first install succeeds");
        let error = slot
            .install(&mut second)
            .expect_err("second install must fail");

        assert_eq!(error, HookBoundaryError::AlreadyInstalled);
        assert_eq!(second.state(), HookState::Failed);
        assert_eq!(slot.current()(5), 15);
    }

    #[test]
    fn explicit_skip_records_no_install_decision() {
        let mut slot = SyntheticHookSlot::new(target as SyntheticFn);

        slot.skip();

        assert_eq!(slot.state(), HookState::Skipped);
        assert_eq!(slot.current()(5), 6);
    }

    #[test]
    fn raw_hook_plan_accepts_matching_no_write_input() {
        let eligibility = validate_raw_hook_plan(valid_raw_input())
            .expect("matching no-write raw hook plan should validate");

        assert_eq!(eligibility.module_name, "steamui.so");
        assert_eq!(eligibility.architecture, "x86");
        assert_eq!(eligibility.target_address, 0x1200);
        assert_eq!(eligibility.replacement_address, 0x2200);
        assert_eq!(eligibility.state, HookState::Planned);
    }

    #[test]
    fn raw_hook_plan_rejects_empty_module_name() {
        let mut input = valid_raw_input();
        input.module_name = "";

        let error = validate_raw_hook_plan(input).expect_err("empty module must fail");

        assert_eq!(error, HookBoundaryError::EmptyModuleName);
    }

    #[test]
    fn raw_hook_plan_rejects_module_mismatch() {
        let mut input = valid_raw_input();
        input.module_name = "/tmp/steamclient.so";

        let error = validate_raw_hook_plan(input).expect_err("module mismatch must fail");

        assert_eq!(error, HookBoundaryError::ModuleMismatch);
    }

    #[test]
    fn raw_hook_plan_rejects_architecture_mismatch() {
        let mut input = valid_raw_input();
        input.actual_architecture = "x86_64";

        let error = validate_raw_hook_plan(input).expect_err("architecture mismatch must fail");

        assert_eq!(error, HookBoundaryError::UnsupportedArchitecture);
    }

    #[test]
    fn raw_hook_plan_rejects_null_target() {
        let mut input = valid_raw_input();
        input.target_address = 0;

        let error = validate_raw_hook_plan(input).expect_err("null target must fail");

        assert_eq!(error, HookBoundaryError::NullTargetAddress);
    }

    #[test]
    fn raw_hook_plan_rejects_null_replacement() {
        let mut input = valid_raw_input();
        input.replacement_address = 0;

        let error = validate_raw_hook_plan(input).expect_err("null replacement must fail");

        assert_eq!(error, HookBoundaryError::NullReplacementAddress);
    }

    #[test]
    fn raw_hook_plan_rejects_target_outside_executable_range() {
        let mut input = valid_raw_input();
        input.target_address = 0x2000;

        let error = validate_raw_hook_plan(input).expect_err("out-of-range target must fail");

        assert_eq!(error, HookBoundaryError::TargetOutsideExecutableRange);
    }

    #[test]
    fn raw_hook_plan_rejects_write_request() {
        let mut input = valid_raw_input();
        input.write_requested = true;

        let error = validate_raw_hook_plan(input).expect_err("write request must fail");

        assert_eq!(error, HookBoundaryError::WritesNotAllowed);
    }

    #[test]
    fn raw_hook_action_gate_accepts_validate_only() {
        let decision =
            evaluate_raw_hook_action(valid_raw_input(), RawHookRequestedAction::ValidateOnly)
                .expect("validate-only action should pass for eligible input");

        assert_eq!(decision.action, RawHookRequestedAction::ValidateOnly);
        assert_eq!(decision.eligibility.module_name, "steamui.so");
        assert_eq!(decision.state, HookState::Planned);
    }

    #[test]
    fn raw_hook_action_gate_rejects_install_action() {
        let error = evaluate_raw_hook_action(valid_raw_input(), RawHookRequestedAction::Install)
            .expect_err("install action must fail in no-write phase");

        assert_eq!(error, HookBoundaryError::InstallationNotAllowed);
    }

    #[test]
    fn raw_hook_action_gate_rejects_invalid_validate_only_input() {
        let mut input = valid_raw_input();
        input.module_name = "/tmp/steamclient.so";

        let error = evaluate_raw_hook_action(input, RawHookRequestedAction::ValidateOnly)
            .expect_err("invalid validate-only input must fail");

        assert_eq!(error, HookBoundaryError::ModuleMismatch);
    }

    #[test]
    fn patch_plan_accepts_validate_only_no_write_input() {
        let decision = validate_patch_plan(valid_patch_plan_input())
            .expect("valid no-write patch plan should pass");

        assert_eq!(decision.action, RawHookRequestedAction::ValidateOnly);
        assert_eq!(decision.module_name, "steamui.so");
        assert_eq!(decision.architecture, "x86");
        assert_eq!(decision.encoding, PatchEncoding::X86RelativeJump32);
        assert_eq!(decision.required_patch_bytes, 5);
        assert_eq!(decision.available_patch_bytes, 8);
        assert_eq!(decision.relative_displacement, 0xffb);
        assert!(decision.would_require_memory_permission_change);
        assert_eq!(decision.state, HookState::Planned);
    }

    #[test]
    fn patch_plan_rejects_install_action() {
        let mut input = valid_patch_plan_input();
        input.action = RawHookRequestedAction::Install;

        let error = validate_patch_plan(input).expect_err("install action must fail");

        assert_eq!(error, HookBoundaryError::InstallationNotAllowed);
    }

    #[test]
    fn patch_plan_rejects_short_patch_length() {
        let mut input = valid_patch_plan_input();
        input.available_patch_bytes = 4;

        let error = validate_patch_plan(input).expect_err("short patch range must fail");

        assert_eq!(error, HookBoundaryError::PatchLengthTooSmall);
    }

    #[test]
    fn patch_plan_rejects_memory_write_request() {
        let mut input = valid_patch_plan_input();
        input.memory_write_requested = true;

        let error = validate_patch_plan(input).expect_err("write request must fail");

        assert_eq!(error, HookBoundaryError::WritesNotAllowed);
    }

    #[test]
    fn patch_plan_rejects_out_of_range_relative_jump() {
        let mut input = valid_patch_plan_input();
        input.raw.replacement_address = 0x9000_0000;

        let error = validate_patch_plan(input).expect_err("out-of-range jump must fail");

        assert_eq!(error, HookBoundaryError::RelativeJumpOutOfRange);
    }

    #[test]
    fn synthetic_patch_simulation_marks_test_owned_buffer() {
        let plan = validate_patch_plan(valid_patch_plan_input())
            .expect("valid no-write patch plan should pass");
        let mut buffer = [0x90; 12];

        let report = simulate_synthetic_patch(&mut buffer, &plan, 2)
            .expect("synthetic patch simulation should pass");

        assert_eq!(report.patch_offset, 2);
        assert_eq!(report.patched_len, 5);
        assert_eq!(report.buffer_len, 12);
        assert_eq!(report.state, HookState::Planned);
        assert_eq!(&buffer[..2], &[0x90, 0x90]);
        assert_eq!(&buffer[2..7], &[0xD5; 5]);
        assert_eq!(&buffer[7..], &[0x90; 5]);
    }

    #[test]
    fn synthetic_patch_simulation_rejects_small_buffer() {
        let plan = validate_patch_plan(valid_patch_plan_input())
            .expect("valid no-write patch plan should pass");
        let mut buffer = [0x90; 4];

        let error = simulate_synthetic_patch(&mut buffer, &plan, 0)
            .expect_err("small synthetic buffer must fail");

        assert_eq!(error, HookBoundaryError::SyntheticBufferTooSmall);
    }

    #[test]
    fn synthetic_patch_simulation_rejects_outside_range() {
        let plan = validate_patch_plan(valid_patch_plan_input())
            .expect("valid no-write patch plan should pass");
        let mut buffer = [0x90; 8];

        let error = simulate_synthetic_patch(&mut buffer, &plan, 4)
            .expect_err("out-of-range synthetic patch must fail");

        assert_eq!(error, HookBoundaryError::SyntheticPatchOutsideBuffer);
    }
}
