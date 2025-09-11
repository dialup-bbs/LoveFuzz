 # LoveFuzz - cc65 `da65` Disassembler Fuzzer

 ## Overview
 
LoveFuzz is a fuzz testing suite designed to identify and analyze bugs in the `da65` disassembler, a key component of the `cc65` toolchain for 6502-based systems. The primary goal is to ensure the robustness and correctness of `da65` by performing automated "round-trip" tests.
 
 ## Methodology
 
 The fuzzer, `lovefuzz.py`, employs a round-trip testing methodology which is a highly effective way to validate the integrity of a disassembler/assembler pair. The process is as follows:
 
 1.  **Generate Source:** A pseudo-random, but syntactically valid, assembly source file (`.s`) is created.
 2.  **Assemble (Pass 1):** The `cl65` utility assembles the source code into an initial binary program.
 3.  **Disassemble:** The `da65` disassembler is invoked to convert the binary back into assembly source code. Optionally, an `.info` file can be generated to guide this process.
 4.  **Patch (Conditional):** A post-processing step is available to apply workarounds for known bugs to the disassembled output. This allows the fuzzer to uncover new issues that might otherwise be masked. This step can be disabled with the `--no-patch` flag. **Note:** The patching logic is currently a placeholder and does not yet apply any fixes.
 5.  **Re-assemble (Pass 2):** The `cl65` utility attempts to re-assemble the patched assembly source back into a second binary.
 6.  **Verify:** The initial binary and the re-assembled binary are compared byte-for-byte. A mismatch or a failure during any step indicates a bug, and the failing test case is saved for analysis.

## Testing Methods

The `lovefuzz.py` script employs two primary methods to ensure the robustness of the toolchain and the fuzzer itself:

*   **Static Advanced Syntax Test**: When run with the `--test-advanced-syntax` flag, the script executes a deterministic, hand-crafted test (`test_static_advanced_directives`). This test uses a static assembly source file containing complex nested directives like `.proc`, `.scope`, and `.if/.else` to verify that the toolchain can correctly handle a round-trip with these advanced features.

*   **Randomized Round-Trip Fuzzing**: This is the core of the fuzzer, implemented within the main execution loop. It follows the round-trip methodology described previously, but uses pseudo-randomly generated assembly source as its starting point. This process is designed to uncover unexpected bugs by testing a wide range of inputs.
 
 ## Findings
 
 This fuzzing campaign has successfully identified two distinct bugs in the `da65` disassembler, with the analysis documented below.
 
 ### Bug 1: `DA65-SEGMENT-SCOPE` (Identified)
 
 *   **Summary:** `da65` fails to correctly emit a `.segment "CODE"` directive after processing a data range (e.g., `TYPE = BYTETABLE`) specified in an `.info` file.
 *   **Root Cause & Impact:** This issue stems from `da65`'s design, which requires explicit segment boundaries in the `.info` file. The disassembler does not automatically revert to the `CODE` segment after a data range unless a new `SEGMENT` or `RANGE` directive for code immediately follows. This behavior contradicts the official `da65` documentation (section 4.5), which states that the disassembler should automatically revert. The practical impact is that subsequent instructions are incorrectly placed within a data segment (e.g., `.segment "RODATA"`), causing the `ca65` assembler to fail during re-assembly.
 *   **Status:** **Identified**. A conditional patching step (`apply_patches`) exists as a placeholder for a future workaround. The intent is to mitigate this bug to allow the fuzzer to uncover other issues that might be masked. As of now, this step performs no actions. The `--no-patch` flag can be used to disable this placeholder step.
 
 ### Bug 2: `DA65-ADDR-MODE` (Exposed)
 
 *   **Summary:** `da65` incorrectly guesses the addressing mode for certain ambiguous 6502 opcodes.
 *   **Impact:** The 6502 instruction set has opcodes that are used for multiple addressing modes (e.g., zeropage vs. absolute). `da65` must use heuristics to guess the correct mode. The fuzzer has generated numerous binaries where `da65` makes the wrong guess. For example, it might disassemble a zeropage instruction as an absolute one. When `ca65` attempts to re-assemble this output, it encounters a mismatch between the opcode and the operand size, resulting in a `Range error (Address size 2 does not match fragment size 1)`.
 *   **Status:** **Exposed**. The fuzzer now consistently generates multiple test cases that trigger this specific error, providing a valuable corpus for debugging `da65`'s static analysis logic.
 
 ## How to Run
 
 1.  **Prerequisites:** Ensure the `cc65` toolchain is installed and that `da65`, `cl65`, and `ca65` are in your system's `PATH`.
 2.  **Execution:** Run the fuzzer from the command line:
     ```bash
     # Run 100 tests with default settings
     python3 lovefuzz.py 100

     # Run 500 tests, generating 200 instructions each, and only log failed tests
     python3 lovefuzz.py 500 -n 200 --log-failed-only

     # Run a test with advanced syntax and data range generation
     python3 lovefuzz.py 10 --test-advanced-syntax --test-da65-ranges

     # Run tests but disable the post-disassembly patching step
     python3 lovefuzz.py 20 --no-patch

     # Run indefinitely until 5 failed tests are found, using brief terminal output
     python3 lovefuzz.py 5 --collect-failed --brief

     # Run indefinitely until 10 passed tests are collected and saved to the 'passed/' directory
     python3 lovefuzz.py 10 --collect-passed

     # Clear all previous logs and artifacts before starting a new run
     python3 lovefuzz.py --clear-log-all
     ```
 3.  **Output:**
    *   A detailed log of test runs is written to `fuzz_test_log.txt`. The `--log-failed-only` or `--log-passed-only` flags can be used to filter the log.
    *   When a test fails, all of its artifacts (the original source, generated binaries, logs, etc.) are saved to a uniquely named subdirectory inside the `failed/` directory for persistent analysis.
    *   If using `--collect-passed`, artifacts from successful runs are saved to the `passed/` directory.
    *   The `--clear-log-all`, `--clear-log-failed`, and `--clear-log-passed` flags can be used to clean up these artifacts.

