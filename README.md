# HView-Linux

HView-Linux is a terminal hex editor and binary analysis tool for Linux x86-64.

The application provides Text and Hex views. Code supports x86, ARM, Thumb, and ARM64 instructions.

The application also provides safe editing, sessions, macros, and executable analysis tools.

## Requirements

Use a Linux x86-64 system with a UTF-8 terminal.

Install Rust 1.98.0 and Cargo to build the application. Install Python 3, `binutils`, and `acl` to run all checks.

The repository contains the required Capstone and Keystone shared libraries. The build does not require a system installation of these libraries.

The current checked package references GLIBC_2.34 as its highest glibc symbol version. Later builds can change this measured floor.

The package needs compatible system `libc`, dynamic loader, `libgcc_s`, `libm`, and `libstdc++` libraries. This GNU package does not support musl-only systems.

## Build and run

Build the release executable from the locked dependencies:

```sh
cargo build --locked --release
```

Run the executable with one or more files or file masks:

```sh
target/release/hview-linux sample.bin
target/release/hview-linux --mode code --entry-point sample.exe
target/release/hview-linux --mode hex --offset 20 --recursive '*.bin'
```

Quote a file mask to prevent shell expansion. Use `--` before a file name that starts with a hyphen.

Run the native engine check:

```sh
target/release/hview-linux --self-test
```

## Install a checked package

Build a package in a new directory:

```sh
python3 scripts/package.py
```

The command prints the new package path. You can also give the command a new output directory.

```sh
python3 scripts/package.py /tmp/hview-linux-package
```

Copy the complete package directory to the installation location. Keep both shared libraries beside the executable.

The package contains the executable, shared libraries, dependency notices, native metadata, this README, and the configuration sample.

The package manifest gives the SHA-256 hash and size of each packaged file.

## Command options

| Option | Action |
| --- | --- |
| `--mode text\|hex\|code` | The option selects the initial view mode. |
| `--offset HEX` | The option selects a hexadecimal file offset. |
| `--virtual HEX` | The option uses retained legacy virtual-address selection. |
| `--entry-point` | The option uses retained legacy entry-point selection. |
| `--end` | The option selects the final byte. |
| `--config PATH` | The option reads the specified configuration file. |
| `--session PATH` | The option reads and writes the specified session file. |
| `--macro PATH` | The option plays the specified startup macro. |
| `--recursive` | The option enables recursion for following file masks. |
| `--help` | The option shows command help without an interactive terminal. |

The application also accepts the verified legacy `/O`, `/SAV`, `/INI`, `/MACRO0`, and `/s` forms.

For PE files, `--virtual` accepts an RVA or preferred ImageBase VA. Different valid RVA and VA results cause an error.

For mapped ELF files, `--virtual` accepts a link-time VA. ELF relocatable files have no virtual-address mapping.

Large PE and ELF files use bounded metadata reads for `--virtual` and `--entry-point`. These reads do not load the complete file.

For buffered plain files, `--virtual` uses the value as a file offset.

Large plain files show the existing format limit and use file offset zero.

`--entry-point` supports mapped ELF entries and the retained DOS executable calculation.

## Main keys

| Key | Action |
| --- | --- |
| `Alt+H` | The key shows or closes help. |
| `Alt+W` | The key changes Text wrapping. |
| `Alt+A` or `Enter` | The key opens the selected architecture assembler during Code editing. |
| `Alt+E` | The key starts editing. |
| `Ctrl+Z` | The key undoes one operation during editing. |
| `Ctrl+Y` | The key redoes one operation during editing. |
| `Alt+M` or `M` | The key selects Text, Hex, or Code mode outside editing. |
| `Enter` | Outside editing, the key selects mode in Text/Hex or follows a direct branch in Code. |
| `Backspace` | In Code view outside editing, the key returns from a followed branch. |
| `Alt+G` | The key goes to a file offset. |
| `Alt+L` | The key shows the current Text line-feed capability notice. |
| `Alt+F` | The key starts an ASCII or masked hexadecimal search. |
| `Alt+R` | The key finds the next match. |
| `Alt+B` | The key finds the previous match. |
| `Alt+S` | The key saves active buffered or paged edits. |
| `Alt+O` | The key opens the file browser outside editing. |
| `Ctrl+S` | The key saves the current data to a new file. |
| `Ctrl+T` | The key opens the analysis tools. |
| `Alt+P` | The key opens the previous input file. |
| `Alt+N` | The key opens the next input file. |
| `O` | The key cycles automatic x86 Code modes and raw x86 widths. |
| `H`, `J`, `K`, or `L` | These keys move the cursor outside editing. |
| `Esc` | The key cancels editing or closes the current screen. |
| `Ctrl+Q` | The key exits the application or closes the file browser. |

Arrow, Home, End, Page Up, and Page Down keys also move the cursor.

Linux terminals send the same byte for `Ctrl+M` and `Enter`. Both keys follow a branch in Code view outside editing.

Code navigation follows direct relative calls, jumps, conditional branches, and loops. Indirect branches and invalid targets produce a notice.

Backspace restores the file offset and viewport from a separate history of up to 256 return positions.

Hex search accepts complete byte pairs and wildcard nibbles. For example, enter `48 8B ?? A? ?F`.

## Configuration

The application loads one configuration file. The application uses the first applicable item in this list:

1. The path from `--config`.
2. `hview-linux.ini` beside the executable.
3. `$XDG_CONFIG_HOME/hview-linux/hview-linux.ini` when `XDG_CONFIG_HOME` is absolute.
4. `$HOME/.config/hview-linux/hview-linux.ini` in other cases.

Set `HVIEW_PORTABLE=1` to stop automatic lookup after the file beside the executable. An explicit `--config` path still has precedence.

Start a native configuration file with this exact header:

```ini
[HView-Linux 1]
```

Use UTF-8 and LF line endings. The parser accepts semicolon comments outside quoted values.

Copy `hview-linux.ini.example` to an applicable `hview-linux.ini` path. Change only settings that you need.

| Setting | Accepted values and effect |
| --- | --- |
| `StartMode` | `Text`, `Hex`, or `Code` selects the initial mode. |
| `Wrap` | `Auto`, `On`, or `Off` controls Text wrapping. |
| `Tab` | `Auto`, `On`, or `Off` controls Text tab expansion. |
| `LineFeed` | `Auto`, `CRLF`, `CR`, or `LF` selects Text line separation. |
| `AutoCodeSize` | `On` uses the detected executable width for automatic x86 Code. |
| `DefaultCodeSize` | `16`, `32`, or `64` selects the other default code size. |
| `DisassemblySyntax` | `Intel` or `ATT` selects the x86 Code display syntax. |
| `InvalidCode` | `Error` stops at invalid input. `Byte` shows one x86 byte or one ARM-family unit. |
| `OpcodeShowBytes` | A value from `0` through `15` sets the displayed opcode byte count. |
| `HexDelimiterChar` | A numeric value from `1` through `255` selects the Hex delimiter byte. |
| `ShowOffset` | `Local` selects supported offset display. `Global` is not reconstructed. |
| `PackNops` | `On` or `Off` controls repeated NOP packing. |
| `PackInt3` | `On` or `Off` controls repeated INT3 packing. |
| `SaveFileAtExit` | `On` or `Off` controls automatic session saving. |
| `SaveFile` | A quoted path selects the automatic session file. |

Automatic ARM-family PE and ELF selection does not depend on `AutoCodeSize`.

The native x86 default is Intel disassembly syntax. Select `DisassemblySyntax=ATT` only when you need x86 AT&T display syntax.

The default invalid-instruction behavior is `InvalidCode=Error`. Select `InvalidCode=Byte` to continue with architecture data units.

X86 uses one-byte `db` rows. ARM-family data uses one architecture unit, which can be shorter at the file end.

X86 assembly input always uses Intel syntax. The x86 assembler prompt also shows Intel syntax with AT&T display.

ARM and Thumb assembly input uses native syntax.

Without a raw model, press `O` after effective 64-bit x86 Code to select Real16. The Code header shows `Real16`.

Real16 applies the retained real-mode instruction policy. A native saved session preserves this selection in a versioned Linux extension.

Real16 rejects protected-mode-only instruction forms. Real16 wraps displayed relative branch targets to the 16-bit address range.

The parser reports unknown settings and invalid values. The application can import verified legacy configuration files with the `[HViewIni 5.03]` header.

## Analysis tools

Press `Ctrl+T`, and then select one tool:

| Key | Tool |
| --- | --- |
| `A` | The tool converts supported file and virtual addresses. PE also supports RVA. |
| `R` | The tool selects an explicit raw address model or restores `AUTO`. |
| `S` | The tool finds printable ASCII and ASCII encoded as UTF-16LE or UTF-16BE. |
| `P` | The tool browses supported executable structures. |
| `E` | The tool shows an entropy map in bits per byte. Press `Escape` to cancel its work. |
| `D` | The tool compares the current buffer with another file at equal offsets. |
| `I` | The tool shows signed and unsigned integers at the cursor. |
| `X` | The tool applies a repeating hexadecimal XOR mask during editing. |
| `F` | The tool fills an edit range with a repeating hexadecimal pattern. |

All analysis tools use the current buffer. Therefore, the tools include unsaved edits.

The address tool is separate from retained command-line address selection. The tool reports checked file, RVA, and VA results without legacy fallbacks.

PE parsing supports exact PE32 and PE32+ file-backed mappings. File gaps and overlays keep file addresses.

Automatic PE Code supports x86, x64, ARM, Thumb, and ARM64 machine and class pairs. PE ARMNT Code remains unsupported.

Virtual-only section tails have no file bytes. The PE browser limits output to 10,000 rows.

ELF parsing supports little-endian ELF32 and ELF64 ET_REL, ET_EXEC, and ET_DYN files.

Mapped PT_LOAD bytes use declared link-time VAs. File gaps use file offsets, and zero-fill tails have no file bytes.

Automatic ELF Code supports i386, x86-64, AArch64, and ARM. An ARM entry selects ARM or Thumb from its entry-state bits.

ELF relocatable files use file offsets and have no automatic ARM state. Select an explicit ARM or Thumb raw model when necessary.

The ELF browser shows headers, entries, program records, and section records. The browser does not inspect symbols or relocations.

HView-Linux does not apply runtime rebasing to ELF addresses. The ELF browser limits output to 10,000 rows.

The ELF browser validates all section names and escapes names only for retained rows.
If retained ELF row text exceeds 16 MiB, the browser returns an error.

Code mode can also decode raw x86, ARM, Thumb, and ARM64 bytes.

### Raw address model

Press `Ctrl+T`, and then press `R`. Enter one complete raw model:

- `AUTO`
- `X86 16|32|64 LE|BE HEXBASE`
- `ARM|THUMB|ARM64 LE|BE HEXBASE`

For example, `X86 64 LE 140000000` maps file offset zero to hexadecimal address `140000000`.

The raw model overrides executable metadata for addresses, architecture, decoding, assembly, and branch navigation.

The address tool converts file offsets and virtual addresses.

The raw model rejects RVA conversion. The selected byte order controls integer inspection. All instruction engines use little-endian bytes.

ARM and Thumb use generic native backends. The application does not apply a CPU-version gate.

ARM64 supports decoding. ARM64 assembly is not supported.

Raw 16-bit mode uses a linear 32-bit address range. Raw 16-bit mode does not use the Real16 instruction policy or wrapped targets.

With a raw x86 model active, `O` cycles 16-bit, 32-bit, and 64-bit widths. The application checks the address range before changing width.

For an ARM-family raw model, use `Ctrl+T`, and then use `R` to select a different architecture.

`AUTO` restores the previous automatic code width and Real16 selection. Changes to the raw base or architecture clear branch-return history.

Changes to byte order alone preserve branch-return history. Invalid, canceled, and unchanged model selections also preserve that history.

Raw settings survive mode changes, Save, Save As, and edit cancellation. File switches and application restarts clear raw settings.

Sessions store the underlying automatic width and Real16 selection. Sessions do not store the raw model. Modern session persistence remains planned work.

String results use a four-character minimum and a 120-character display limit. String and comparison browsers limit output to 10,000 rows.

The entropy tool uses blocks of at least 4,096 bytes. The tool increases the block size for large files.

Entropy and Compare run as bounded cancellable work and use current source stamps. Progress shows on the active editor frame.

Press `Esc` to cancel Entropy or Compare. Canceled work returns no partial results.
The other analysis tools remain synchronous.

## Editing and saving

Buffered files through 64 MiB support all editing and saving operations in this section.

Larger regular files support in-memory Hex nibble replacement, undo, redo, and explicit cancellation.
Paged Hex overtype cannot extend the file at EOF.
Paged Save and Save As stream logical bytes through bounded private staging files.
File switching and quit remain unavailable until paged edits are saved or canceled.

Press `Alt+E` to start editing. Hex mode replaces nibbles. Code mode assembles one instruction for the selected architecture.

Press `Esc` to cancel all active edits.
Buffered cancellation restores its complete memory baseline.
Paged cancellation restores the captured logical source layout.

During Code editing, `Alt+A` or `Enter` opens the selected architecture assembly prompt. A preview shows the proposed patch before buffer changes.

The preview shows exact bytes, mapped addresses, affected instructions, retained bytes, overwritten bytes, and extension beyond EOF.

Preview x86 text uses the selected disassembly syntax. X86 assembly input and prompt text use Intel syntax. ARM-family text uses native syntax.

Press `Enter` to apply the exact proposed bytes. Press `Esc` to cancel the preview.

The preview requires at least 60 columns and enough rows for the complete patch summary. A resize notice prevents application below those dimensions.

The preview marks clipped instruction rows. The replacement instruction must decode completely, including when `InvalidCode=Byte` is active.

Press `Ctrl+Z` to undo one operation during editing. Press `Ctrl+Y` to redo one operation.

One completed hexadecimal byte, confirmed assembly patch, Fill range, or XOR range forms one edit record.

Undo and redo restore bytes, buffer length, cursor, viewport, and nibble selection. A changed edit clears redo history.

Failed, canceled, and unchanged edits preserve redo history. The history holds up to 256 records within 130 MiB of stored bytes.

The application removes the oldest records when necessary. An operation larger than the history byte limit fails before buffer changes.

Press `Alt+S` to replace the current file.
Press `Ctrl+S` to save the current data under a new name.

Successful saves establish a new edit baseline and clear both histories. Prepublication failures preserve edits and both histories.

A paged final synchronization warning adopts the verified published baseline. The warning states that new bytes can already be visible.

A published replacement reopen failure closes the unusable view and prevents SAV publication. The independent original backup remains available.

A published Save As reopen failure retains the original source, edits, and histories. Edit cancellation clears both histories.

An in-place save checks read-time file identity, original bytes, metadata, and an advisory file lock before publication.
Buffered Save and existing-session replacement refuse a different inode, even when its bytes match the original bytes.

The replacement keeps the owner, group, permission mode, user xattrs, and POSIX access ACL. The replacement receives a new inode.

The save keeps the original bytes in a private `.HView-save-*` directory beside the target. The backup keeps original access and modification timestamps.

The save rejects symbolic links, multiple hard links, set-user-ID files, set-group-ID files, and unsupported privileged metadata.

Save As atomically refuses an existing destination entry. Successful publication flushes the staged files and their parent directory.

Advisory locks only coordinate with programs that use compatible locks. An uncooperative writer can change the target during the final rename interval.

Do not write the same file concurrently from another program.

A final synchronization failure can leave visible new bytes and recovery files. Read the displayed recovery path before further file changes.

## Sessions and macros

Use `--session PATH` to enable one session file. `SaveFileAtExit=On` enables the configured session file.

A session stores 1 through 24 files. Each stored path must contain fewer than 260 ASCII bytes.

New sessions store absolute Linux paths. A decoded session payload cannot exceed 16 MiB.

A session cannot add Real16 state when unknown data occupies the Linux extension area.

Unicode file paths work without session storage. A session cannot store a Unicode path.

The application imports verified legacy compressed sessions. It preserves verified unknown payload bytes when it updates a session.

Use `--macro PATH` to play one verified legacy `HViewMacro` file at startup. A macro can contain at most 1,024 records.

Macro records can contain delays, repetition, key modifiers, and stop-on-notice behavior. Press `Esc` to cancel active playback.

The macro delay field supports values through 4,294,967,295 milliseconds. Escape cancels a maximum delay promptly.

The application keeps terminal input that arrives during a macro delay. A macro file is an imported binary format; the application has no macro recorder.

## Memory and format limits

The application reads regular files through 64 MiB into memory. Editing keeps another complete buffer until you save or cancel edits.

Larger regular files open in a bounded Hex view. The view reads visible data in windows of at most 64 KiB.

Paged Hex edits use bounded logical spans and stay in memory.
The view keeps at most 256 undo records within the 130 MiB history limit.
Press `Esc` to discard those edits and restore source bytes.

Large-file Text, Code display, format tools, structural edit controls, search, and analysis remain pending parity work.

Large-file PE and ELF startup can select a checked entry point or virtual address through bounded metadata reads.

Compare accepts regular-file peers above 64 MiB through windows of at most 64 KiB.
Peers through 64 MiB still use buffered storage.
Compare rejects nonregular peers and preserves readable virtual regular-file contents.

Text mode supports byte-oriented text. Text mode reports UTF-16 text and directs the user to Hex or Code mode.

The structure browser and address conversion support PE and ELF files.

ELF support is limited to little-endian ELF32 and ELF64 files without runtime rebasing.

Large-file structure browsing and Code display remain pending work.

## Native components and licenses

Code display uses Capstone 5.0.9. Assembly uses Keystone 0.9.2.

Bounded Text indexing uses unicode-segmentation 1.13.3 and unicode-width 0.2.2.
The `licenses` directory contains their copyright notice and Apache 2.0 or MIT license options.
The release package includes these four Unicode notice files.

The application first loads `libcapstone.so` and `libkeystone.so` beside the executable. Development builds can use the repository `lib` directory as a fallback.

Set `HVIEW_PORTABLE=1` to disable the development fallback. The release package check uses this setting from an isolated working directory.

`lib/native-dependencies.json` records upstream sources, source revisions, wheel hashes, member hashes, delivered hashes, transformations, and notice hashes.

The delivered Keystone library has no inherited RPATH. The metadata records the verified Patchelf transformation that removed the upstream wheel RPATH.

The package check verifies all recorded native hashes. The check also rejects native RPATH, RUNPATH, AUDIT, and DEPAUDIT tags.

The HView-Linux Rust source currently has no declared license. Each dependency keeps its applicable upstream notice files.

Review the source license state and all native notice files before redistribution.

## Verification

Run the local checks:

```sh
cargo fmt --all -- --check
cargo test --locked --all-targets -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
target/release/hview-linux --self-test
python3 tests/terminal_probe.py target/release/hview-linux
python3 tests/file_workflow_probe.py target/release/hview-linux
python3 tests/reliability_probe.py target/release/hview-linux
python3 tests/analysis_probe.py target/release/hview-linux
python3 tests/macro_probe.py target/release/hview-linux
python3 tests/linux_behavior_probe.py target/release/hview-linux
python3 tests/navigation_probe.py target/release/hview-linux
python3 tests/raw_model_probe.py target/release/hview-linux
python3 tests/patch_probe.py target/release/hview-linux
python3 tests/edit_history_probe.py target/release/hview-linux
python3 tests/paged_lifecycle_probe.py target/release/hview-linux
python3 scripts/package.py /tmp/hview-linux-package
```

The CI workflow and package command run every application probe. The package command uses the packaged executable with portable native loading.
