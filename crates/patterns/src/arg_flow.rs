//! Linear tracking of where a function's arguments end up.
//!
//! Byte patterns pin the registers and stack slots a compiler happened to pick,
//! so a rebuild that only reallocates registers breaks them. Following each
//! argument through register copies and stack spills instead yields facts that
//! survive that: which argument is stored at which offset of which other
//! argument, what a call was passed, and what the function returns.
//!
//! The walk is linear from the entry and stops at the first return or
//! unconditional jump, so it describes the straight-line path only. Callers
//! must require every fact they rely on to be unambiguous rather than assume
//! the walk saw every path.

use std::collections::HashMap;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};

/// Arguments the tracker seeds, which covers every function it is used on.
const TRACKED_ARGUMENTS: u8 = 6;
/// System V integer argument registers, in order.
const SYSV_ARGUMENTS: [Register; TRACKED_ARGUMENTS as usize] = [
    Register::RDI,
    Register::RSI,
    Register::RDX,
    Register::RCX,
    Register::R8,
    Register::R9,
];
const CALLER_SAVED_64: [Register; 9] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];
const CALLER_SAVED_32: [Register; 3] = [Register::RAX, Register::RCX, Register::RDX];
/// Call arguments recorded per call site.
pub const CALL_ARGUMENTS: usize = 4;

/// A value the tracker can name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Value {
    /// The traced function's own argument, by position.
    Arg(u8),
    /// A constant the function loaded or pushed, sign-extended.
    Imm(i64),
    /// What the call at this code offset returned.
    Returned(usize),
}

/// `mov [object + offset], value`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Store {
    pub ip: usize,
    pub object: Value,
    pub offset: i64,
    pub width: usize,
    /// `None` when the stored value is not one the tracker can name.
    pub value: Option<Value>,
}

/// A read-modify-write of `[object + offset]`, such as a refcount decrement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Update {
    pub ip: usize,
    pub object: Value,
    pub offset: i64,
    pub width: usize,
    pub mnemonic: Mnemonic,
    /// The immediate operand, sign-extended, when there is one.
    pub operand: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Call {
    pub ip: usize,
    /// Code offset of a direct call's target; `None` for an indirect call.
    pub target: Option<usize>,
    /// The first arguments as the callee receives them.
    pub args: [Option<Value>; CALL_ARGUMENTS],
}

#[derive(Debug, Default)]
pub struct Trace {
    pub stores: Vec<Store>,
    pub updates: Vec<Update>,
    pub calls: Vec<Call>,
    /// The return register at the first `ret`, if the walk reached one.
    pub returned: Option<Value>,
}

/// Walk at most `limit` bytes of the function at `offset` in `code`.
///
/// Instruction addresses in the result are offsets into `code`, so the caller
/// can compare them with other resolved offsets directly.
pub fn trace(bitness: u32, code: &[u8], offset: usize, limit: usize) -> Trace {
    let mut trace = Trace::default();
    let Some(window) = code.get(offset..) else {
        return trace;
    };
    let window = &window[..window.len().min(limit)];
    let mut decoder = Decoder::with_ip(bitness, window, offset as u64, DecoderOptions::NONE);
    let mut factory = InstructionInfoFactory::new();
    let mut instruction = Instruction::default();
    let mut state = State::entry(bitness);

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            break;
        }
        match instruction.flow_control() {
            FlowControl::Return => {
                trace.returned = state.registers.get(&Register::RAX).copied();
                break;
            }
            FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => break,
            FlowControl::Call | FlowControl::IndirectCall => {
                state.call(&instruction, &mut trace);
                continue;
            }
            _ => {}
        }
        state.step(&instruction, &mut factory, &mut trace);
    }
    trace
}

enum Location {
    /// A stack slot, as an offset from the stack pointer at entry.
    Stack(i64),
    /// A field of an object the tracker can name.
    Object(Value, i64),
}

struct State {
    bitness: u32,
    registers: HashMap<Register, Value>,
    stack: HashMap<i64, Value>,
    /// Stack pointer relative to its value at entry, while it is known.
    sp: Option<i64>,
    /// The frame pointer's value relative to the entry stack pointer, while
    /// it holds one.
    fp: Option<i64>,
}

impl State {
    fn entry(bitness: u32) -> Self {
        let mut registers = HashMap::new();
        let mut stack = HashMap::new();
        for position in 0..TRACKED_ARGUMENTS {
            if bitness == 64 {
                registers.insert(SYSV_ARGUMENTS[position as usize], Value::Arg(position));
            } else {
                // cdecl: the return address sits at entry esp, arguments above it.
                stack.insert(4 + 4 * i64::from(position), Value::Arg(position));
            }
        }
        Self {
            bitness,
            registers,
            stack,
            sp: Some(0),
            fp: None,
        }
    }

    fn pointer_size(&self) -> i64 {
        i64::from(self.bitness / 8)
    }

    fn call(&mut self, instruction: &Instruction, trace: &mut Trace) {
        let target = matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
        .then(|| instruction.near_branch_target() as usize);
        let mut args = [None; CALL_ARGUMENTS];
        for (position, arg) in args.iter_mut().enumerate() {
            *arg = if self.bitness == 64 {
                self.registers.get(&SYSV_ARGUMENTS[position]).copied()
            } else {
                self.sp
                    .and_then(|sp| self.stack.get(&(sp + 4 * position as i64)).copied())
            };
        }
        trace.calls.push(Call {
            ip: instruction.ip() as usize,
            target,
            args,
        });
        let clobbered: &[Register] = if self.bitness == 64 {
            &CALLER_SAVED_64
        } else {
            &CALLER_SAVED_32
        };
        for register in clobbered {
            self.registers.remove(register);
        }
        self.registers
            .insert(Register::RAX, Value::Returned(instruction.ip() as usize));
    }

    fn step(
        &mut self,
        instruction: &Instruction,
        factory: &mut InstructionInfoFactory,
        trace: &mut Trace,
    ) {
        let op0 = instruction.op0_kind();
        match instruction.mnemonic() {
            Mnemonic::Mov if op0 == OpKind::Register => {
                let destination = instruction.op0_register();
                let full = destination.full_register();
                let source = (instruction.op1_kind() == OpKind::Register)
                    .then(|| instruction.op1_register().full_register());
                if full == Register::RBP && source == Some(Register::RSP) {
                    self.registers.remove(&Register::RBP);
                    self.fp = self.sp;
                } else if full == Register::RSP && source == Some(Register::RBP) {
                    self.sp = self.fp;
                } else {
                    // A byte or word write leaves the rest of the register stale.
                    let value = (destination.size() >= 4)
                        .then(|| self.operand(instruction, 1))
                        .flatten();
                    self.write_register(full, value);
                }
                return;
            }
            Mnemonic::Mov if op0 == OpKind::Memory => {
                let value = self.operand(instruction, 1);
                self.store(instruction, value, trace);
                return;
            }
            Mnemonic::Xor
                if op0 == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                    && instruction.op0_register() == instruction.op1_register() =>
            {
                self.write_register(
                    instruction.op0_register().full_register(),
                    Some(Value::Imm(0)),
                );
                return;
            }
            Mnemonic::Push => {
                let value = self.operand(instruction, 0);
                let size = -i64::from(instruction.stack_pointer_increment());
                if let Some(sp) = self.sp.as_mut() {
                    *sp -= size;
                    let slot = *sp;
                    self.set_stack(slot, value);
                }
                return;
            }
            Mnemonic::Pop => {
                let value = self.sp.and_then(|sp| self.stack.get(&sp).copied());
                if let Some(sp) = self.sp.as_mut() {
                    *sp += i64::from(instruction.stack_pointer_increment());
                }
                if op0 == OpKind::Register {
                    self.write_register(instruction.op0_register().full_register(), value);
                }
                return;
            }
            Mnemonic::Sub | Mnemonic::Add
                if op0 == OpKind::Register
                    && instruction.op0_register().full_register() == Register::RSP =>
            {
                let delta = signed_immediate(instruction, 1);
                self.sp = match (self.sp, delta) {
                    (Some(sp), Some(delta)) if instruction.mnemonic() == Mnemonic::Sub => {
                        Some(sp - delta)
                    }
                    (Some(sp), Some(delta)) => Some(sp + delta),
                    _ => None,
                };
                return;
            }
            Mnemonic::Lea
                if op0 == OpKind::Register
                    && instruction.op0_register().full_register() == Register::RSP =>
            {
                self.sp = match self.location(instruction) {
                    Some(Location::Stack(slot)) => Some(slot),
                    _ => None,
                };
                return;
            }
            Mnemonic::Sub | Mnemonic::Add | Mnemonic::Inc | Mnemonic::Dec
                if op0 == OpKind::Memory =>
            {
                if let Some(Location::Object(object, offset)) = self.location(instruction) {
                    trace.updates.push(Update {
                        ip: instruction.ip() as usize,
                        object,
                        offset,
                        width: instruction.memory_size().size(),
                        mnemonic: instruction.mnemonic(),
                        operand: signed_immediate(instruction, 1),
                    });
                }
            }
            _ => {}
        }

        // Anything not modelled above forgets what it may have overwritten.
        if op0 == OpKind::Memory {
            if let Some(Location::Stack(slot)) = self.location(instruction) {
                let info = factory.info(instruction);
                if info
                    .used_memory()
                    .iter()
                    .any(|memory| is_write(memory.access()))
                {
                    self.stack.remove(&slot);
                }
            }
        }
        let written: Vec<Register> = factory
            .info(instruction)
            .used_registers()
            .iter()
            .filter(|used| is_write(used.access()))
            .map(|used| used.register().full_register())
            .collect();
        for register in written {
            self.write_register(register, None);
        }
    }

    fn write_register(&mut self, register: Register, value: Option<Value>) {
        if register == Register::RSP {
            self.sp = None;
            return;
        }
        if register == Register::RBP {
            self.fp = None;
        }
        match value {
            Some(value) => {
                self.registers.insert(register, value);
            }
            None => {
                self.registers.remove(&register);
            }
        }
    }

    fn set_stack(&mut self, slot: i64, value: Option<Value>) {
        match value {
            Some(value) => {
                self.stack.insert(slot, value);
            }
            None => {
                self.stack.remove(&slot);
            }
        }
    }

    fn store(&mut self, instruction: &Instruction, value: Option<Value>, trace: &mut Trace) {
        let width = instruction.memory_size().size();
        match self.location(instruction) {
            Some(Location::Stack(slot)) => {
                let value =
                    value.filter(|_| width as i64 == 4 || width as i64 == self.pointer_size());
                self.set_stack(slot, value);
            }
            Some(Location::Object(object, offset)) => trace.stores.push(Store {
                ip: instruction.ip() as usize,
                object,
                offset,
                width,
                value,
            }),
            None => {}
        }
    }

    fn operand(&self, instruction: &Instruction, operand: u32) -> Option<Value> {
        match instruction.op_kind(operand) {
            OpKind::Register => self
                .registers
                .get(&instruction.op_register(operand).full_register())
                .copied(),
            OpKind::Memory => match self.location(instruction)? {
                Location::Stack(slot) => self.stack.get(&slot).copied(),
                Location::Object(..) => None,
            },
            _ => signed_immediate(instruction, operand).map(Value::Imm),
        }
    }

    fn location(&self, instruction: &Instruction) -> Option<Location> {
        if instruction.memory_index() != Register::None
            || matches!(instruction.memory_segment(), Register::FS | Register::GS)
        {
            return None;
        }
        let base = instruction.memory_base().full_register();
        if base == Register::None || base == Register::RIP {
            return None;
        }
        let displacement = if self.bitness == 64 {
            instruction.memory_displacement64() as i64
        } else {
            i64::from(instruction.memory_displacement32() as i32)
        };
        if base == Register::RSP {
            return self.sp.map(|sp| Location::Stack(sp + displacement));
        }
        if base == Register::RBP {
            if let Some(fp) = self.fp {
                return Some(Location::Stack(fp + displacement));
            }
        }
        self.registers
            .get(&base)
            .map(|&object| Location::Object(object, displacement))
    }
}

fn is_write(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite
    )
}

fn signed_immediate(instruction: &Instruction, operand: u32) -> Option<i64> {
    Some(match instruction.op_kind(operand) {
        OpKind::Immediate8 => i64::from(instruction.immediate8() as i8),
        OpKind::Immediate16 => i64::from(instruction.immediate16() as i16),
        OpKind::Immediate32 => i64::from(instruction.immediate32() as i32),
        OpKind::Immediate64 => instruction.immediate64() as i64,
        OpKind::Immediate8to16 => i64::from(instruction.immediate8to16()),
        OpKind::Immediate8to32 => i64::from(instruction.immediate8to32()),
        OpKind::Immediate8to64 => instruction.immediate8to64(),
        OpKind::Immediate32to64 => instruction.immediate32to64(),
        _ => return None,
    })
}
