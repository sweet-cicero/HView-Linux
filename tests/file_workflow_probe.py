#!/usr/bin/env python3
"""Check Linux arguments, configuration, files, macros, and sessions."""

# These imports provide native path, process, payload, and disposable-file operations.
# The terminal helper owns pseudoterminal execution and restoration checks.
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

from terminal_probe import run_session


# These key sequences select quit, editing, saving, file switching, and the file picker.
# Tests send the exact terminal bytes used by the application.
CTRL_Q = b"\x11"
CTRL_S = b"\x13"
CTRL_Y = b"\x19"
CTRL_Z = b"\x1a"
ALT_E = b"\x1be"
ALT_N = b"\x1bn"
ALT_O = b"\x1bo"
ALT_P = b"\x1bp"
ALT_S = b"\x1bs"
DOWN = b"\x1b[B"


# This helper returns the smallest native configuration for one startup mode.
# Callers write the returned bytes to each precedence fixture.
def native_config(mode: str) -> bytes:
    """Make a small native configuration file."""
    return f"[HView-Linux 1]\nStartMode={mode}\n".encode()


# This helper builds one fixed legacy macro record from a key and modifiers.
# The application later parses the returned bytes during startup.
def macro_file(key: int, modifiers: int = 0) -> bytes:
    """Make one legacy macro event."""
    data = bytearray(69)
    data[:10] = b"HViewMacro"
    data[14:16] = (0x9006).to_bytes(2, "little")
    data[16:18] = (1).to_bytes(2, "little")
    data.extend(bytes([modifiers]))
    data.extend(key.to_bytes(4, "little"))
    return bytes(data)


# This helper duplicates the SAV checksum for controlled payload changes.
# The updated checksum keeps the modified fixture valid for the preservation check.
def checksum(data: bytes) -> int:
    """Calculate the saved payload checksum."""
    full = len(data) & ~3
    value = 0
    for byte in reversed(data[full:]):
        value = ((value << 9) + byte) & 0xFFFFFFFF
    value = (value * 8) & 0xFFFFFFFF
    for offset in range(0, full, 4):
        rotated = ((value << 1) | (value >> 31)) & 0xFFFFFFFF
        word = int.from_bytes(data[offset : offset + 4], "little")
        value = (value + rotated + word) & 0xFFFFFFFF
    return value


# This assertion helper searches captured terminal bytes for one required value.
# A missing value reports the caller-supplied reason.
def require(output: bytes, text: bytes, reason: str) -> None:
    """Require terminal output text."""
    if text not in output:
        raise AssertionError(reason)


# This helper redirects a disposable parent symbolic link after the application accepts its read.
# The next Save must compare the writable target with the retained read descriptor.
def redirect_parent(parent: Path, destination: Path) -> None:
    """Redirect a parent symbolic link."""
    parent.unlink()
    parent.symlink_to(destination, target_is_directory=True)


# This entry point runs each workflow in one disposable directory.
# Every application process uses the shared terminal-restoration check.
def main() -> None:
    """Run the file workflow checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: file_workflow_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    # The first process checks terminal-free help and the current UTF-8 CLI boundary.
    # Later native picker checks cover non-UTF-8 paths without changing CLI parsing.
    help_result = subprocess.run(
        [binary, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if help_result.returncode != 0 or b"--session PATH" not in help_result.stdout:
        raise AssertionError("Help did not work without a terminal.")
    invalid = subprocess.run(
        [os.fsencode(binary), b"bad-\xff"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if invalid.returncode == 0 or b"not valid UTF-8" not in invalid.stderr:
        raise AssertionError("A non-UTF-8 argument did not produce a clear error.")

    with tempfile.TemporaryDirectory(prefix="hview-files-") as temporary:
        # The first fixtures check explicit offsets, End, Unicode paths, and option boundaries.
        # Each file contains small deterministic bytes for the buffered viewer.
        root = Path(temporary)
        data_file = root / "data.bin"
        data_file.write_bytes(bytes(range(32)))
        output = run_session(
            binary,
            ["--mode", "hex", "--offset", "10", str(data_file)],
            [CTRL_Q],
        )
        require(output, b"00000010", "The native offset did not select byte 0x10.")
        output = run_session(binary, ["--mode=hex", "--end", str(data_file)], [CTRL_Q])
        require(output, b"0000001F", "The end option did not select the final byte.")

        unicode_file = root / "r\N{LATIN SMALL LETTER E WITH ACUTE}sum\N{LATIN SMALL LETTER E WITH ACUTE}.bin"
        unicode_file.write_bytes(b"Unicode path")
        run_session(binary, [str(unicode_file)], [CTRL_Q])

        hyphen_file = root / "-literal.bin"
        hyphen_file.write_bytes(b"Hyphen path")
        old_directory = Path.cwd()
        try:
            os.chdir(root)
            run_session(binary, ["--", hyphen_file.name], [CTRL_Q])
        finally:
            os.chdir(old_directory)

        # This section checks explicit, sibling, XDG, portable, and invalid configuration paths.
        # The copied binary gives sibling discovery a controlled executable directory.
        copied = root / "bin" / "hview-linux"
        copied.parent.mkdir()
        shutil.copy2(binary, copied)
        xdg = root / "xdg"
        xdg_config = xdg / "hview-linux" / "hview-linux.ini"
        xdg_config.parent.mkdir(parents=True)
        xdg_config.write_bytes(native_config("Hex"))
        environment = os.environ.copy()
        environment.pop("HVIEW_PORTABLE", None)
        environment["XDG_CONFIG_HOME"] = str(xdg)
        output = run_session(copied, [str(data_file)], [CTRL_Q], environment)
        require(output, b"00000000:", "The XDG configuration did not select Hex mode.")

        sibling_config = copied.with_name("hview-linux.ini")
        sibling_config.write_bytes(native_config("Text"))
        output = run_session(copied, [str(data_file)], [CTRL_Q], environment)
        require(output, b"W Unwrap", "The sibling configuration did not have precedence.")

        explicit_config = root / "explicit.ini"
        explicit_config.write_bytes(native_config("Hex"))
        output = run_session(
            copied,
            ["--config", str(explicit_config), str(data_file)],
            [CTRL_Q],
            environment,
        )
        require(output, b"00000000:", "The explicit configuration did not have precedence.")

        sibling_config.unlink()
        environment["HVIEW_PORTABLE"] = "1"
        output = run_session(copied, [str(data_file)], [CTRL_Q], environment)
        require(output, b"W Unwrap", "Portable mode did not skip XDG configuration.")
        environment.pop("HVIEW_PORTABLE")

        invalid_config = root / "invalid.ini"
        invalid_config.write_bytes(
            b"[HView-Linux 1]\nDisassemblySyntax=Unsupported\n"
        )
        output = run_session(
            binary,
            ["--config", str(invalid_config), str(data_file)],
            [],
            expected_code=1,
        )
        require(output, b"Illegal value", "An invalid syntax setting did not fail.")

        # This section checks macro startup and recursive path expansion.
        # The recursive view must reach a child file through normal file switching.
        macro = root / "quit.mac"
        macro.write_bytes(macro_file(ord("Q"), 2))
        run_session(binary, ["--macro", str(macro), str(data_file)], [])

        recursive = root / "recursive"
        (recursive / "child").mkdir(parents=True)
        (recursive / "a.bin").write_bytes(b"A")
        (recursive / "child" / "b.bin").write_bytes(b"B")
        output = run_session(
            binary,
            ["--recursive", str(recursive / "*.bin")],
            [ALT_N, CTRL_Q],
        )
        require(output, b"b.bin", "Recursive file expansion did not include the child file.")

        # This section opens a picker result and checks session restart and active-file selection.
        # A second session stores and restores a moved buffered cursor.
        picker = root / "picker"
        picker.mkdir()
        first = picker / "a-first.bin"
        second = picker / "b-picked.bin"
        first.write_bytes(b"First")
        second.write_bytes(b"Second")
        session = root / "state.sav"
        output = run_session(
            binary,
            ["--session", str(session), str(first)],
            [ALT_O, DOWN, DOWN, b"\r", CTRL_Q],
        )
        require(output, b"b-picked.bin", "The file picker did not open the selected file.")
        if not session.is_file():
            raise AssertionError("The explicit session file was not published.")

        output = run_session(binary, ["--session", str(session)], [ALT_P, CTRL_Q])
        require(output, b"a-first.bin", "Previous-file selection did not open the first file.")
        output = run_session(binary, ["--session", str(session)], [CTRL_Q])
        require(output, b"a-first.bin", "The active file did not survive restart.")

        view_config = root / "view.ini"
        view_config.write_bytes(native_config("Hex"))
        view_session = root / "view.sav"
        run_session(
            binary,
            ["--config", str(view_config), "--session", str(view_session), str(first)],
            [b"\x1b[C", ALT_O, DOWN, DOWN, b"\r", ALT_P, CTRL_Q],
        )
        view_payload = view_session.read_bytes()[32:]
        active = int.from_bytes(view_payload[:4], "little")
        final_offset = int.from_bytes(view_payload[384:392], "little")
        if (active, final_offset) != (0, 1):
            raise AssertionError("File switching did not restore the current view offset.")

        # This section changes one unknown SAV payload byte and repairs its checksum.
        # A normal session update must preserve the unknown byte.
        saved = bytearray(session.read_bytes())
        if saved[24:28] != b"\0\0\0\0":
            raise AssertionError("The native saved fixture is unexpectedly compressed.")
        payload = saved[32:]
        payload[100000] = 0x53
        saved[32:] = payload
        saved[28:32] = checksum(payload).to_bytes(4, "little")
        session.write_bytes(saved)
        run_session(binary, ["--session", str(session)], [CTRL_Q])
        if session.read_bytes()[32 + 100000] != 0x53:
            raise AssertionError("A session update changed an unknown payload byte.")

        # This section redirects a buffered source to another file with identical accepted bytes.
        # Failed Save must preserve Undo and Redo before two successful Saves renew the retained identity.
        save_first = root / "save-first"
        save_second = root / "save-second"
        save_first.mkdir()
        save_second.mkdir()
        original = save_first / "sample.bin"
        other = save_second / "sample.bin"
        original.write_bytes(b"\x12")
        other.write_bytes(b"\x12")
        save_parent = root / "save-parent"
        save_parent.symlink_to(save_first, target_is_directory=True)
        output = run_session(
            binary,
            ["--mode=hex", "--offset=0", str(save_parent / "sample.bin")],
            [
                ALT_E,
                b"a",
                lambda: redirect_parent(save_parent, save_second),
                ALT_S,
                b"\r",
                (81, 24, CTRL_Z, b"00000000:  12"),
                (80, 24, CTRL_Y, b"00000000:  A2"),
                lambda: redirect_parent(save_parent, save_first),
                ALT_S,
                ALT_E,
                b"b",
                ALT_S,
                CTRL_Q,
            ],
        )
        require(output, b"changed outside the editor", "Save accepted a different matching file.")
        if original.read_bytes() != b"\xB2" or other.read_bytes() != b"\x12":
            raise AssertionError("Buffered Save did not preserve and renew the accepted identity.")
        backups = [path.read_bytes() for path in save_first.glob(".HView-save-*/original.bin")]
        if sorted(backups) != [b"\x12", b"\xA2"]:
            raise AssertionError("Repeated buffered Save did not preserve each preceding baseline.")
        if any(save_second.glob(".HView-save-*")):
            raise AssertionError("Refused buffered Save created a recovery directory.")

        # This section saves edited bytes through a parent symbolic link.
        # Save As must retain the resolved destination and its descriptor when the parent link later changes.
        copy_source = root / "copy-source.bin"
        copy_source.write_bytes(b"\x12")
        copy_parent = root / "copy-parent"
        copy_parent.symlink_to(save_first, target_is_directory=True)
        copy_other = save_second / "copy.bin"
        copy_other.write_bytes(b"\xA2")
        run_session(
            binary,
            ["--mode=hex", "--offset=0", str(copy_source)],
            [
                ALT_E,
                b"a",
                CTRL_S,
                str(copy_parent / "copy.bin").encode(),
                # Require successful publication before the parent redirect changes the destination.
                (80, 24, b"\r", "↓FUO --------".encode()),
                lambda: redirect_parent(copy_parent, save_second),
                ALT_E,
                b"b",
                ALT_S,
                CTRL_Q,
            ],
        )
        if (save_first / "copy.bin").read_bytes() != b"\xB2":
            raise AssertionError("Save As did not retain its published destination and identity.")
        if copy_source.read_bytes() != b"\x12" or copy_other.read_bytes() != b"\xA2":
            raise AssertionError("Save after Save As changed another file.")

        # This section redirects the session path after startup reads its accepted bytes.
        # Session publication must refuse the different matching file before any recovery directory exists.
        session_first = root / "session-first"
        session_second = root / "session-second"
        session_first.mkdir()
        session_second.mkdir()
        accepted_session = session.read_bytes()
        (session_first / "state.sav").write_bytes(accepted_session)
        (session_second / "state.sav").write_bytes(accepted_session)
        session_parent = root / "session-parent"
        session_parent.symlink_to(session_first, target_is_directory=True)
        output = run_session(
            binary,
            ["--session", str(session_parent / "state.sav")],
            [b"\x1b[C", lambda: redirect_parent(session_parent, session_second), CTRL_Q],
            expected_code=1,
        )
        require(output, b"changed outside the editor", "Session publication accepted another matching file.")
        for directory in (session_first, session_second):
            if (directory / "state.sav").read_bytes() != accepted_session:
                raise AssertionError("Refused session publication changed a session file.")
            if any(directory.glob(".HView-save-*")):
                raise AssertionError("Refused session publication created a recovery directory.")

        # This section checks Windows path rejection and native path persistence limits.
        # An unrepresentable session path must leave native viewing available.
        windows_session = Path(__file__).parent / "fixtures" / "offset-10.sav"
        output = run_session(
            binary,
            ["--session", str(windows_session)],
            [],
            expected_code=1,
        )
        require(output, b"Windows syntax", "A Windows session path did not fail clearly.")

        # A legacy session cannot represent this valid native path.
        # The notice disables session publication while the native file view remains available.
        excluded_session = root / "unicode-state.sav"
        output = run_session(
            binary,
            ["--session", str(excluded_session), str(unicode_file)],
            [b"\r", CTRL_Q],
        )
        require(output, b"260 ASCII bytes", "A Unicode session path did not show its limit.")
        require(output, b"HView-Linux", "A session path limit blocked the native file view.")
        if excluded_session.exists():
            raise AssertionError("An invalid session was published.")

        # Linux treats a backslash as a literal pathname byte.
        # Session restart must reopen the exact absolute file.
        backslash_file = root / "name\\part.bin"
        backslash_file.write_bytes(b"Backslash path")
        backslash_session = root / "backslash.sav"
        output = run_session(
            binary,
            ["--session", str(backslash_session), str(backslash_file)],
            [CTRL_Q],
        )
        output = run_session(binary, ["--session", str(backslash_session)], [CTRL_Q])
        require(output, b"name\\part.bin", "A Linux backslash path did not survive restart.")

        # This section changes the working directory after one relative input becomes an absolute session path.
        # Restart must open the original file and never reinterpret the saved path.
        first_directory = root / "first-directory"
        second_directory = root / "second-directory"
        first_directory.mkdir()
        second_directory.mkdir()
        (first_directory / "same.bin").write_bytes(b"FIRST DIRECTORY")
        (second_directory / "same.bin").write_bytes(b"SECOND DIRECTORY")
        relative_session = root / "relative.sav"
        old_directory = Path.cwd()
        try:
            os.chdir(first_directory)
            run_session(
                binary,
                ["--session", str(relative_session), "same.bin"],
                [CTRL_Q],
            )
            os.chdir(second_directory)
            output = run_session(binary, ["--session", str(relative_session)], [CTRL_Q])
        finally:
            os.chdir(old_directory)
        require(output, b"FIRST DIRECTORY", "A relative session path opened a different file.")
        if b"SECOND DIRECTORY" in output:
            raise AssertionError("A session used the restart working directory.")

        # This final section initializes an inactive UTF-16 file in explicit Hex mode.
        # The stored mode and offset must remain available when the file becomes active.
        utf16_file = root / "utf16.bin"
        utf16_file.write_bytes("\N{ZERO WIDTH NO-BREAK SPACE}Text".encode("utf-16-le"))
        utf16_session = root / "utf16.sav"
        output = run_session(
            binary,
            [
                "--mode=hex",
                "--offset=1",
                "--session",
                str(utf16_session),
                str(data_file),
                str(utf16_file),
            ],
            [b"m", b"t\r", ALT_N, CTRL_Q],
        )
        if not utf16_session.is_file():
            raise AssertionError("Explicit Hex mode did not initialize the UTF-16 session file.")
        utf16_payload = utf16_session.read_bytes()[32:]
        second_base = 8 + 2814
        active = int.from_bytes(utf16_payload[:4], "little")
        mode = int.from_bytes(utf16_payload[second_base + 2772 : second_base + 2776], "little")
        offset = int.from_bytes(utf16_payload[second_base + 376 : second_base + 384], "little")
        if (active, mode, offset) != (1, 2, 1):
            raise AssertionError("The inactive session record lost its startup mode or offset.")

    print("File workflow probe passed.")


if __name__ == "__main__":
    main()
