#!/usr/bin/env python3
"""LoveFuzz - A fuzz tester for the cc65 toolchain (ca65/da65)."""

import argparse
import subprocess
import random
import os
import sys
import filecmp
import re
import shutil
from collections import defaultdict
import tempfile
from contextlib import contextmanager
from typing import List

# --- Configuration ---
# Assumes cc65 binaries (cl65, da65) are in the system's PATH
CA65_PATH = "ca65"
LD65_PATH = "ld65"
DA65_PATH = "da65"
LOG_FILE = "fuzz_test_log.txt"
START_ADDR = 0x0800

# 6502 Opcodes and their supported addressing modes for the generator.
# 'acc' is accumulator, 'impl' is implied.
OPCODES = {
    "ADC": ["imm", "zp", "zpx", "abs", "absx", "absy", "indx", "indy"],
    "AND": ["imm", "zp", "zpx", "abs", "absx", "absy", "indx", "indy"],
    "ASL": ["acc", "zp", "zpx", "abs", "absx"],
    "BIT": ["zp", "abs"],
    "CLC": ["impl"], "SEC": ["impl"], "CLI": ["impl"], "SEI": ["impl"],
    "CLD": ["impl"], "SED": ["impl"], "CLV": ["impl"],
    "CMP": ["imm", "zp", "zpx", "abs", "absx", "absy", "indx", "indy"],
    "CPX": ["imm", "zp", "abs"],
    "CPY": ["imm", "zp", "abs"],
    "DEC": ["zp", "zpx", "abs", "absx"],
    "EOR": ["imm", "zp", "zpx", "abs", "absx", "absy", "indx", "indy"],
    "INC": ["zp", "zpx", "abs", "absx"],
    "INX": ["impl"], "DEX": ["impl"], "INY": ["impl"], "DEY": ["impl"],
    "JMP": ["abs", "ind"],
    "JSR": ["abs"],
    "LDA": ["imm", "zp", "zpx", "abs", "absx", "absy", "indx", "indy"],
    "LDX": ["imm", "zp", "zpy", "abs", "absy"],
    "LDY": ["imm", "zp", "zpx", "abs", "absx"],
    "LSR": ["acc", "zp", "zpx", "abs", "absx"],
    "NOP": ["impl"],
    "ORA": ["imm", "zp", "zpx", "abs", "absx", "absy", "indx", "indy"],
    "PHA": ["impl"], "PLA": ["impl"], "PHP": ["impl"], "PLP": ["impl"],
    "ROL": ["acc", "zp", "zpx", "abs", "absx"],
    "ROR": ["acc", "zp", "zpx", "abs", "absx"],
    "RTI": ["impl"], "RTS": ["impl"],
    "SBC": ["imm", "zp", "zpx", "abs", "absx", "absy", "indx", "indy"],
    "STA": ["zp", "zpx", "abs", "absx", "absy", "indx", "indy"],
    "STX": ["zp", "zpy", "abs"],
    "STY": ["zp", "zpx", "abs"],
    "TAX": ["impl"], "TXA": ["impl"], "TAY": ["impl"], "TYA": ["impl"],
    "TSX": ["impl"], "TXS": ["impl"],
}

# 6502 Relative Branching Opcodes
BRANCH_OPCODES = ["BCC", "BCS", "BEQ", "BNE", "BPL", "BMI", "BVC", "BVS"]
MAX_RECENT_LABELS = 2

ADVANCED_SYNTAX_TEST_SOURCE = """
; === cc65 Advanced Directives Fuzzer Example ===

.segment "CODE"

; Define a macro to stress expansion inside scopes & procs
.macro WriteColor addr, val
    LDA #val
    STA addr
.endmacro


; === First procedure with nested scopes and conditionals ===
.proc InitSystem
    SEI             ; disable interrupts (safe environment)
    LDA #$00
    STA $D020       ; clear border

    .scope VideoSetup
        LDA #$06
        STA $D021   ; set background

        ; Conditional block with nested levels
        .if 1
            WriteColor $0400, $41
            .if 0
                ; unreachable branch
                WriteColor $0401, $42
            .else
                .if 1
                    WriteColor $0402, $43
                .else
                    WriteColor $0403, $44
                .endif
            .endif
        .else
            WriteColor $0404, $99
        .endif
    .endscope

    CLI             ; re-enable interrupts
    RTS
.endproc


; === Second procedure: multiple scopes crossing ===
.proc UpdateState
    LDX #$05
    LDY #$10

    .scope Arithmetic
        TXA
        CLC
        ADC #$20
        STA $C000

        .scope NestedArith
            TYA
            SEC
            SBC #$08
            STA $C001

            .if 1
                WriteColor $C002, $55
            .endif
        .endscope
    .endscope

    RTS
.endproc


; === Global conditional structure outside procs ===
.if 1
    .scope GlobalScope
        LDA #$77
        STA $D800         ; write into color RAM
    .endscope
.endif
"""

# --- Instruction Generators ---

class InstructionGenerator:
    """Base class for instruction generators."""
    def __init__(self, opcodes):
        self.opcodes = opcodes
        self.all_pairs = [(op, mode) for op, modes in opcodes.items() for mode in modes]

    def select_instruction(self):
        """Returns a tuple of (opcode, mode)."""
        raise NotImplementedError

class RandomGenerator(InstructionGenerator):
    """Selects instructions completely randomly."""
    def select_instruction(self):
        opcode = random.choice(list(self.opcodes.keys()))
        mode = random.choice(self.opcodes[opcode])
        return opcode, mode

class DeterministicCoverageGenerator(InstructionGenerator):
    """
    Generates each instruction form exactly once per cycle in a random order.
    """
    def __init__(self, opcodes):
        super().__init__(opcodes)
        random.shuffle(self.all_pairs)
        self.index = 0

    def select_instruction(self):
        if self.index >= len(self.all_pairs):
            # Reshuffle and start over if we've exhausted the list
            random.shuffle(self.all_pairs)
            self.index = 0
        opcode, mode = self.all_pairs[self.index]
        self.index += 1
        return opcode, mode

class HybridCoverageGenerator(InstructionGenerator):
    """
    A coverage-guided random generator. It gives a higher probability to
    instruction forms that have been generated less frequently.
    """
    def __init__(self, opcodes):
        super().__init__(opcodes)
        self.coverage = defaultdict(int)

    def select_instruction(self):
        weights = [1.0 / (self.coverage.get((op, mode), 0) + 1) for op, mode in self.all_pairs]
        opcode, mode = random.choices(self.all_pairs, weights=weights, k=1)[0]
        self.coverage[(opcode, mode)] += 1
        return opcode, mode

    def get_coverage_stats(self):
        """Returns the number of covered forms and total forms."""
        covered = sum(1 for count in self.coverage.values() if count > 0)
        total = len(self.all_pairs)
        return covered, total

class StructEnumFuzzer:
    """Generates .struct and .enum definitions and usages."""
    def __init__(self):
        self.struct_counter = 0
        self.enum_counter = 0
        self.defined_structs = {}  # name -> [member_names]
        self.defined_enums = {}    # name -> [member_names]

    def _new_struct_name(self):
        name = f"FuzzStruct_{self.struct_counter}"
        self.struct_counter += 1
        return name

    def _new_enum_name(self):
        name = f"FuzzEnum_{self.enum_counter}"
        self.enum_counter += 1
        return name

    def gen_struct_def(self) -> str:
        """Generates a .struct definition block."""
        struct_name = self._new_struct_name()
        members = []
        member_names = []
        for i in range(random.randint(1, 5)):
            member_name = f"member_{i}"
            member_names.append(member_name)
            # Choose a random data type for the member
            member_type = random.choice(['.byte', '.word', '.dword', '.res'])
            if member_type == '.res':
                size = random.randint(1, 8)
                members.append(f"    {member_name} .res {size}")
            else:
                members.append(f"    {member_name} {member_type}")
        
        self.defined_structs[struct_name] = member_names
        
        code = [f".struct {struct_name}"]
        code.extend(members)
        code.append(".endstruct\n")
        return "\n".join(code)

    def gen_enum_def(self) -> str:
        """Generates an .enum definition block."""
        enum_name = self._new_enum_name()
        members = []
        member_names = []
        current_val = 0
        for i in range(random.randint(2, 8)):
            member_name = f"MEMBER_{enum_name.upper()}_{i}"
            member_names.append(member_name)
            
            # 50% chance to assign a value explicitly
            if random.random() < 0.5:
                # 30% chance to use a previous enum member in an expression
                if i > 0 and random.random() < 0.3:
                    prev_member = random.choice(member_names[:-1])
                    op = random.choice(['+', '|', '^'])
                    val_expr = f"{prev_member} {op} {1 << random.randint(0,3)}"
                    members.append(f"    {member_name} = {val_expr}")
                else:
                    val = random.randint(current_val, current_val + 10)
                    members.append(f"    {member_name} = ${val:02X}")
                    current_val = val + 1
            else:
                members.append(f"    {member_name}")
                current_val += 1

        self.defined_enums[enum_name] = member_names
        
        code = [f".enum {enum_name}"]
        code.extend(members)
        code.append(".endenum\n")
        return "\n".join(code)

    def gen_struct_instance(self, label_name: str) -> str:
        """Generates a struct instantiation using .tag."""
        if not self.defined_structs:
            return ""
        struct_name = random.choice(list(self.defined_structs.keys()))
        return f"{label_name}: .tag {struct_name}"

    def gen_enum_usage(self) -> str:
        """Generates an instruction that uses a defined enum member."""
        if not self.defined_enums:
            return ""
        enum_name = random.choice(list(self.defined_enums.keys()))
        member_name = random.choice(self.defined_enums[enum_name])
        op = random.choice(["LDA", "CMP", "AND", "ORA", "EOR"])
        return f"    {op} #{enum_name}::{member_name}"

# --- Helper Functions ---

@contextmanager
def temporary_directory():
    """Context manager for creating and cleaning up a temporary directory."""
    temp_dir = tempfile.mkdtemp()
    try:
        yield temp_dir
    finally:
        try:
            shutil.rmtree(temp_dir)
        except OSError as e:
            print(f"Warning: Could not clean up temp directory {temp_dir}: {e}", file=sys.stderr)


def generate_operand(mode: str, test_jmp_bug: bool) -> str:
    """Generates a random operand string for a given addressing mode."""
    if mode == "imm":
        return f"#${random.randint(0, 255):02X}"
    if mode in ("zp", "zpx", "zpy", "indx", "indy"):
        return f"${random.randint(0, 255):02X}"
    if mode in ("abs", "absx", "absy", "ind"):
        # Avoid generating addresses in the zero page for absolute modes
        addr = random.randint(START_ADDR, 0xFFFF)
        if mode == "ind" and not test_jmp_bug:
            # Avoid the JMP ($xxFF) bug unless we are explicitly testing for it.
            while (addr & 0xFF) == 0xFF:
                addr = random.randint(START_ADDR, 0xFFFF)
        return f"${addr:04X}"
    return ""  # For acc, impl


def generate_edge_case_line() -> str | None:
    """
    Attempts to generate a specific edge case instruction.
    Returns a string if an edge case was generated, otherwise None.
    """
    # 20% chance to test the JMP ($xxFF) indirect jump bug
    if random.random() < 0.20:
        # Generate an address on a page boundary (but not in zero page)
        addr = (random.randint(START_ADDR >> 8, 0xFF) << 8) | 0xFF
        return f"    JMP (${addr:04X})"

    return None


def format_instruction(opcode: str, mode: str, test_jmp_bug: bool) -> str:
    """Formats an opcode and mode into a line of assembly."""
    operand = generate_operand(mode, test_jmp_bug)

    line = f"    {opcode} "
    if mode == "acc":
        line += "A"
    elif mode == "ind":
        line += f"({operand})"
    elif mode == "indx":
        line += f"({operand},X)"
    elif mode == "indy":
        line += f"({operand}),Y"
    elif mode in ("zpx", "absx"):
        line += f"{operand},X"
    elif mode in ("zpy", "absy"):
        line += f"{operand},Y"
    else:  # imm, zp, abs, impl
        line += operand
    return line.strip()


def generate_asm_file(filename: str, num_instructions: int, test_jmp_bug: bool, test_interactions: bool, test_advanced: bool, test_da65_ranges: bool, generator: InstructionGenerator) -> List[dict]:
    """Creates a complete .s file with random instructions, including branches."""
    label_counter = 0
    recent_labels: List[str] = []
    # Store macros as {name: num_params}
    defined_macros = {}
    data_ranges = [] # To store info about generated data blocks
    struct_fuzzer = None

    with open(filename, 'w', encoding='utf-8') as f:
        if test_advanced:
            struct_fuzzer = StructEnumFuzzer()
            for _ in range(random.randint(1, 2)):
                f.write(struct_fuzzer.gen_struct_def())
            for _ in range(random.randint(1, 2)):
                f.write(struct_fuzzer.gen_enum_def())

            # Define a symbol for conditional assembly, as shown in context
            f.write(f"FEATURE_FLAG = {random.choice([0, 1])}\n\n")

            # Define 1 or 2 macros with parameters, as shown in context
            num_macros = random.randint(1, 2)
            for i in range(num_macros):
                macro_name = f"M_{i:04X}"
                num_params = random.randint(0, 2)
                defined_macros[macro_name] = num_params
                
                params_str = ", ".join([f"p{j+1}" for j in range(num_params)])
                f.write(f".macro {macro_name} {params_str}\n")
                
                # Macro body with 1 to 3 instructions
                for _ in range(random.randint(1, 3)):
                    if num_params > 0:
                        param_to_use = f"p{random.randint(1, num_params)}"
                        op = random.choice(["LDA", "LDX", "LDY", "CMP", "ADC", "SBC"])
                        f.write(f"    {op} #{param_to_use}\n")
                    else:
                        op = random.choice(["INX", "DEX", "CLC", "SEC", "ASL A", "NOP"])
                        f.write(f"    {op}\n")
                f.write(".endmacro\n\n")

        f.write('.segment "CODE"\n')

        for _ in range(num_instructions):
            current_label = None
            # 20% chance to generate a label before an instruction
            if random.random() < 0.20:
                label = f"L{label_counter:04X}"
                f.write(f"{label}:\n")
                label_counter += 1
                recent_labels.append(label)
                current_label = label
                if len(recent_labels) > MAX_RECENT_LABELS:
                    recent_labels.pop(0)

                # Test for overlapping labels if enabled
                if test_interactions and random.random() < 0.10:
                    overlap_label = f"L{label_counter:04X}"
                    f.write(f"{overlap_label}:\n")
                    label_counter += 1
                    recent_labels.append(overlap_label)
                    current_label = overlap_label # Use the latest label for self-branch test
                    if len(recent_labels) > MAX_RECENT_LABELS:
                        recent_labels.pop(0)

            # 25% chance to generate a branch, if there are labels to branch to
            if recent_labels and random.random() < 0.25:
                opcode = random.choice(BRANCH_OPCODES)

                # Test for self-branch if enabled and a label was just created
                if test_interactions and current_label and random.random() < 0.10:
                    target_label = current_label
                else:
                    target_label = random.choice(recent_labels)

                f.write(f"    {opcode} {target_label}\n")
            else:
                # Decide what to generate: advanced syntax or regular instruction
                roll = random.random()
                
                if test_da65_ranges and roll < 0.05:
                    # Generate a data block (5% chance)
                    data_label = f"Data_{label_counter:04X}"
                    label_counter += 1
                    
                    data_type = random.choice(['.byte', '.word'])
                    num_elements = random.randint(4, 16)
                    
                    if data_type == '.byte':
                        values = [f"${random.randint(0, 255):02X}" for _ in range(num_elements)]
                        data_size = num_elements
                        range_type = 'ByteTable'
                    else: # .word
                        values = [f"${random.randint(0, 65535):04X}" for _ in range(num_elements)]
                        data_size = num_elements * 2
                        range_type = 'WordTable'
                        
                    f.write(f"{data_label}:\n")
                    f.write(f"    {data_type} {', '.join(values)}\n")
                    
                    # Record this data range for the info file
                    data_ranges.append({'name': data_label, 'size': data_size, 'type': range_type})
                elif test_advanced and roll < 0.10 and struct_fuzzer.defined_structs:
                    # Generate a struct instance (5% chance)
                    label = f"StructData_{label_counter:04X}"
                    f.write(struct_fuzzer.gen_struct_instance(label) + '\n')
                    label_counter += 1
                elif test_advanced and roll < 0.15 and struct_fuzzer.defined_enums:
                    # Generate enum usage (5% chance)
                    f.write(struct_fuzzer.gen_enum_usage() + '\n')
                elif test_advanced and roll < 0.20:
                    # Generate a conditional block (5% chance)
                    f.write("    .if FEATURE_FLAG = 1\n")
                    opcode, mode = generator.select_instruction()
                    f.write("    " + format_instruction(opcode, mode, test_jmp_bug) + '\n')
                    if random.random() < 0.5:
                        f.write("    .else\n")
                        opcode, mode = generator.select_instruction()
                        f.write("    " + format_instruction(opcode, mode, test_jmp_bug) + '\n')
                    f.write("    .endif\n")
                elif test_advanced and defined_macros and roll < 0.30:
                    # Generate a macro call (10% chance)
                    macro_name, num_params = random.choice(list(defined_macros.items()))
                    args = [f"${random.randint(0, 255):02X}" for _ in range(num_params)]
                    f.write(f"    {macro_name} {', '.join(args)}\n")
                else:
                    # Generate a regular instruction
                    line = None
                    if test_jmp_bug and random.random() < 0.30:
                        line = generate_edge_case_line()
                    if line is None:
                        opcode, mode = generator.select_instruction()
                        line = format_instruction(opcode, mode, test_jmp_bug)
                    f.write(line + '\n')

        # Ensure the program terminates cleanly.
        # The default linker config for 'none' doesn't add a crt0 that would
        # handle program exit, so we need to ensure our code block ends.
        f.write("    rts\n")
    return data_ranges


def create_linker_config(filename: str) -> None:
    """Creates a minimal linker config file."""
    config = f"""
MEMORY {{
    RAM: start = ${START_ADDR:04X}, size = ${0x10000 - START_ADDR:04X}, file = %O;
}}
SEGMENTS {{
    CODE: load = RAM, type = ro;
}}
"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(config)

def create_c64_linker_config(directory: str) -> str:
    """
    Creates a linker configuration file suitable for testing C64 files.
    The config defines memory regions to accommodate the absolute addresses
    used in the test files and outputs a raw binary.
    """
    config_content = """
MEMORY {
    ZP:     start = $0000, size = $0100, type = rw;
    SCREEN: start = $0400, size = $0400, type = rw;
    MAIN:   start = $0800, size = $B800, type = rw, file = %O;
    CRAM:   start = $C000, size = $1000, type = rw;
    IO:     start = $D000, size = $1000, type = rw;
}
SEGMENTS {
    CODE:    load = MAIN, type = ro, start = $0800;
    RODATA:  load = MAIN, type = ro, optional = yes;
    DATA:    load = MAIN, type = rw, optional = yes;
    BSS:     load = MAIN, type = bss, define = yes, optional = yes;
}
FILES {
    %O: format = bin;
}
"""
    config_path = os.path.join(directory, "c64_test.cfg")
    with open(config_path, "w", encoding='utf-8') as f:
        f.write(config_content)
    return config_path


def run_command(cmd_list: List[str], check: bool = True) -> subprocess.CompletedProcess | None:
    """Executes a command and handles errors."""
    try:
        result = subprocess.run(
            cmd_list,
            check=check,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        return result
    except FileNotFoundError:
        print(f"Error: Command '{cmd_list[0]}' not found. Is cc65 in your PATH?", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error executing: {' '.join(cmd_list)}", file=sys.stderr)
        print(f"Return code: {e.returncode}", file=sys.stderr)
        print(f"Stdout:\n{e.stdout}", file=sys.stderr)
        print(f"Stderr:\n{e.stderr}", file=sys.stderr)
        return None


def hexdump(data: bytes, title: str = "") -> None:
    """Prints a hex dump of binary data."""
    if title:
        print(f"--- {title} ---")

    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'{i:08x}: {hex_part:<48} |{ascii_part}|')
    print("-" * (10 + 48 + 3 + 16))

def test_static_advanced_directives(cpu_type: str) -> bool:
    """
    Performs a ca65 -> da65 -> ca65 round-trip test on the static
    advanced directives assembly file.
    Returns True on success, False on failure.
    """
    print("\n===== Running Static Advanced Directives Test =====")
    with temporary_directory() as temp_dir:
        # Define paths
        asm_path = os.path.join(temp_dir, "advanced_test.s")
        cfg_path = create_c64_linker_config(temp_dir)
        obj1_path = os.path.join(temp_dir, "advanced_test1.o")
        bin1_path = os.path.join(temp_dir, "advanced_test1.prg")
        dasm_path = os.path.join(temp_dir, "advanced_test.dasm.s")
        obj2_path = os.path.join(temp_dir, "advanced_test2.o")
        bin2_path = os.path.join(temp_dir, "advanced_test2.prg")

        # Write static asm to file
        with open(asm_path, 'w', encoding='utf-8') as f:
            f.write(ADVANCED_SYNTAX_TEST_SOURCE)

        # --- Pass 1: Assemble and link original file ---
        print(f"Assembling static file {asm_path}...")
        if not run_command([CA65_PATH, "--cpu", cpu_type, "-t", "c64", asm_path, "-o", obj1_path]):
            return False
        if not run_command([LD65_PATH, "-C", cfg_path, "-o", bin1_path, obj1_path]):
            return False

        # --- Disassemble ---
        # The binary is loaded at $0800 as per the linker config.
        print(f"Disassembling {bin1_path}...")
        if not run_command([DA65_PATH, "--cpu", cpu_type, "--start-addr", hex(START_ADDR), "-o", dasm_path, bin1_path]):
            return False

        # --- Pass 2: Re-assemble and link disassembled file ---
        print(f"Re-assembling {dasm_path}...")
        if not run_command([CA65_PATH, "--cpu", cpu_type, "-t", "c64", dasm_path, "-o", obj2_path]):
            return False
        if not run_command([LD65_PATH, "-C", cfg_path, "-o", bin2_path, obj2_path]):
            return False

        # --- Verification ---
        print("Verifying binaries...")
        if filecmp.cmp(bin1_path, bin2_path, shallow=False):
            print(">>> SUCCESS: Binaries for static advanced test match!")
            return True
        else:
            print(">>> FAILURE: Binaries for static advanced test DO NOT match!")
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write("---- STATIC ADVANCED TEST FAILURE ----\n")
                f.write("--- ORIGINAL ASSEMBLY ---\n")
                f.write(ADVANCED_SYNTAX_TEST_SOURCE)
                f.write("\n--- DISASSEMBLED ASSEMBLY ---\n")
                with open(dasm_path, 'r', encoding='utf-8') as dasm_f:
                    f.write(dasm_f.read())
                f.write("\n")
            with open(bin1_path, 'rb') as f:
                hexdump(f.read(), "HEX DUMP OF ORIGINAL")
            with open(bin2_path, 'rb') as f: # Corrected variable name
                hexdump(f.read(), "HEX DUMP OF RE-ASSEMBLED")
            return False

def parse_map_file(map_path: str) -> dict:
    """Parses a ld65 map file to extract label addresses."""
    labels = {}
    # Regex to find lines like: `L0000      000800 (A)`
    label_re = re.compile(r"^\s*([a-zA-Z_@][a-zA-Z0-9_@]*)\s+([0-9a-fA-F]{6})\s+\(A\)")
    in_exports_section = False
    with open(map_path, 'r', encoding='utf-8') as f:
        for line in f:
            if "Exports:" in line:
                in_exports_section = True
                continue
            if not in_exports_section:
                continue
            
            match = label_re.match(line)
            if match:
                name = match.group(1)
                addr = int(match.group(2), 16)
                labels[name] = addr
    return labels

def generate_da65_info_file(info_path: str, labels: dict, data_ranges: List[dict]) -> None:
    """Generates a da65 info file from a dictionary of labels and data ranges."""
    with open(info_path, 'w', encoding='utf-8') as f:
        f.write("# da65 info file generated by fuzzer\n\n")

        data_labels = {dr['name'] for dr in data_ranges}

        # Write LABEL directives for non-data labels
        for name, addr in labels.items():
            # Don't add linker-generated symbols or data labels to the LABEL section
            if name.startswith('__') or name in data_labels:
                continue
            f.write(f'LABEL {{ NAME "{name}"; ADDR ${addr:04X}; }};\n')

        # Write RANGE directives for data blocks
        for dr in data_ranges:
            name = dr['name']
            if name in labels:
                start_addr = labels[name]
                end_addr = start_addr + dr['size'] - 1
                range_type = dr['type']
                
                f.write(f'RANGE {{ START ${start_addr:04X}; END ${end_addr:04X}; TYPE {range_type}; NAME "{name}"; }};\n')

def main(num_files: int, num_instructions: int, cpu_type: str, test_jmp_bug: bool, test_interactions: bool, test_advanced: bool, test_da65_info: bool, test_da65_ranges: bool, generator: InstructionGenerator) -> None:
    """Main function to run the fuzzing and verification process."""
    if num_files > 0:
        print(f"Starting fuzz test for {num_files} file(s) with {num_instructions} instructions each.")
        print(f"Logging to {LOG_FILE}")

        # Announce generator strategy
        if isinstance(generator, DeterministicCoverageGenerator):
            print("Using deterministic coverage generator.")
        elif isinstance(generator, HybridCoverageGenerator):
            print("Using hybrid coverage-guided generator.")
        else:
            print("Using random generator.")


    # Clear log file
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write("cc65 Assembler/Disassembler Fuzz Test Log\n")
        f.write("=" * 40 + "\n\n")

    success_count = 0
    total_tests = num_files

    if test_advanced:
        total_tests += 1
        if test_static_advanced_directives(cpu_type):
            success_count += 1

    for i in range(num_files):
        test_name = f"random_test_{i}"
        print(f"\n===== Running Test {i+1}/{num_files}: {test_name} =====")

        with temporary_directory() as temp_dir:
            orig_asm_path = os.path.join(temp_dir, f"{test_name}.s")
            cfg_path = os.path.join(temp_dir, f"{test_name}.cfg")
            orig_prg_path = os.path.join(temp_dir, f"{test_name}_orig.prg")
            disasm_path = os.path.join(temp_dir, f"{test_name}_disasm.s")
            reasm_prg_path = os.path.join(temp_dir, f"{test_name}_reasm.prg")
            map_path = os.path.join(temp_dir, f"{test_name}.map")
            info_path = os.path.join(temp_dir, f"{test_name}.info")

            data_ranges = generate_asm_file(orig_asm_path, num_instructions, test_jmp_bug, test_interactions, test_advanced, test_da65_ranges, generator)

            with open(orig_asm_path, 'r', encoding='utf-8') as f:
                original_asm_content = f.read()

            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"---- TEST {i+1}: {test_name} ----\n")
                f.write("--- ORIGINAL ASSEMBLY ---\n")
                f.write(original_asm_content)
                f.write("\n")

            create_linker_config(cfg_path)

            # Define the base cl65 command. --no-target-lib prevents linking a non-existent 'none.lib'.
            cl65_cmd = ["cl65", "--cpu", cpu_type, "--no-target-lib", "-t", "none", "-C", cfg_path]
            if test_da65_info:
                cl65_cmd.extend(["-m", map_path]) # Use cl65's own map file option

            print(f"Assembling {orig_asm_path}...")
            result = run_command(cl65_cmd + ["-o", orig_prg_path, orig_asm_path])
            if not result:
                print("Assembly failed. Skipping test.")
                # Consider logging the failure reason here
                continue

            with open(orig_prg_path, 'rb') as f:
                original_binary = f.read()
            hexdump(original_binary, f"HEX DUMP OF ORIGINAL: {os.path.basename(orig_prg_path)}")

            da65_cmd = ["da65", "--cpu", cpu_type, "--start-addr", hex(START_ADDR), "-o", disasm_path]
            if test_da65_info:
                # Parse map file and generate info file
                labels = parse_map_file(map_path)
                generate_da65_info_file(info_path, labels, data_ranges)
                da65_cmd.extend(["-i", info_path])
            da65_cmd.append(orig_prg_path)

            print(f"Disassembling {orig_prg_path}...")
            result = run_command(da65_cmd)
            if not result:
                print("Disassembly failed. Skipping test.")
                continue

            with open(disasm_path, 'r', encoding='utf-8') as f:
                disassembled_asm_content = f.read()

            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write("--- DISASSEMBLED ASSEMBLY ---\n")
                f.write(disassembled_asm_content)
                f.write("\n")

            print(f"Re-assembling {disasm_path}...")
            result = run_command(cl65_cmd + ["-o", reasm_prg_path, disasm_path])
            if not result:
                print("Re-assembly failed. Skipping test.")
                # Consider logging the failure reason here
                continue

            with open(reasm_prg_path, 'rb') as f:
                reassembled_binary = f.read()
            hexdump(reassembled_binary, f"HEX DUMP OF RE-ASSEMBLED: {os.path.basename(reasm_prg_path)}")

            print("Verifying binaries...")
            if filecmp.cmp(orig_prg_path, reasm_prg_path, shallow=False):
                print(">>> SUCCESS: Binaries match!")
                success_count += 1
                result_str = "SUCCESS"
            else:
                print(">>> FAILURE: Binaries DO NOT match!")
                result_str = "FAILURE"

            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"--- RESULT: {result_str} ---\n\n")

    print("\n" + "="*20 + " OVERALL RESULTS " + "="*20)
    print(f"Tests passed: {success_count}/{total_tests}")
    print(f"Tests failed: {total_tests - success_count}/{total_tests}")
    print("="*57)

    if isinstance(generator, HybridCoverageGenerator):
        covered, total = generator.get_coverage_stats()
        print(f"\nHybrid generator coverage: {covered}/{total} instruction forms ({covered/total:.2%})")

    sys.exit(total_tests - success_count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A fuzz tester for the cc65 toolchain (ca65/ld65 <-> da65).",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "count",
        type=int,
        help="The number of pseudo-random assembly files to generate and test."
    )
    parser.add_argument(
        "-n", "--instructions",
        type=int,
        default=50,
        help="The number of instructions to generate per assembly file. (default: 50)"
    )
    parser.add_argument(
        "--cpu",
        type=str,
        default="6502",
        help="The target CPU (e.g., 6502, 65c02, 6502x). (default: 6502)"
    )
    parser.add_argument(
        "--test-jmp-bug",
        action="store_true",
        default=False,
        help="Enable testing of the JMP ($xxFF) indirect jump bug edge case."
    )
    parser.add_argument(
        "--test-interactions",
        action="store_true",
        default=False,
        help="Enable testing of interaction effects like self-branches and overlapping labels."
    )
    parser.add_argument(
        "--test-advanced-syntax",
        action="store_true",
        default=False,
        help="Enable testing of advanced syntax like macros and conditional assembly."
    )
    parser.add_argument(
        "--test-da65-info",
        action="store_true",
        default=False,
        help="Enable testing of the da65 info file feature for labels."
    )
    parser.add_argument(
        "--test-da65-ranges",
        action="store_true",
        default=False,
        help="Enable testing of da65 RANGE directives for data tables. Implies --test-da65-info."
    )
    parser.add_argument(
        "--generator",
        choices=['random', 'deterministic', 'hybrid'],
        default='random',
        help="The instruction generation strategy to use. (default: random)"
    )
    args = parser.parse_args()

    # --test-da65-ranges implies --test-da65-info
    if args.test_da65_ranges:
        args.test_da65_info = True

    # Instantiate the chosen generator
    if args.generator == 'deterministic':
        generator = DeterministicCoverageGenerator(OPCODES)
    elif args.generator == 'hybrid':
        generator = HybridCoverageGenerator(OPCODES)
    else: # 'random'
        generator = RandomGenerator(OPCODES)

    main(args.count, args.instructions, args.cpu, args.test_jmp_bug, args.test_interactions, args.test_advanced_syntax, args.test_da65_info, args.test_da65_ranges, generator)
