#!/usr/bin/env python3
"""Check analysis workflows through a Linux pseudoterminal."""

# These imports build bounded executable fixtures and disposable terminal sessions.
# The shared terminal helper verifies process exit and terminal restoration.
from pathlib import Path
import os
import struct
import sys
import tempfile

from terminal_probe import run_session


# These byte sequences select the mapped analysis, edit, search, save, and movement controls.
# Each Alt sequence uses the raw Escape-prefixed form parsed by Console.
CTRL_Q = b"\x11"
CTRL_T = b"\x14"
CTRL_Z = b"\x1a"
CTRL_Y = b"\x19"
DOWN = b"\x1b[B"
ENTER = b"\r"
ESC = b"\x1b"
ALT_E = b"\x1be"
ALT_F = b"\x1bf"
ALT_S = b"\x1bs"
ALT_R = b"\x1br"
PAGE_DOWN = b"\x1b[6~"
ALT_B = b"\x1bb"
RIGHT = b"\x1b[C"
LEFT = b"\x1b[D"


# This assertion requires each decoded text item in captured terminal output.
def require(output: bytes, *texts: str) -> None:
    """Require each text value in terminal output."""
    for text in texts:
        if text.encode() not in output:
            raise AssertionError(f"The terminal output lacks: {text}")


# This assertion requires a minimum result count for repeated search positions.
def require_count(output: bytes, text: str, count: int) -> None:
    """Require a minimum number of text occurrences."""
    actual = output.count(text.encode())
    if actual < count:
        raise AssertionError(f"The terminal output contains {actual} instances of {text}. Expected at least {count}.")


# This formatter creates the exact selected-offset header used by result checks.
def header(offset: int) -> str:
    """Return the selected-offset header text."""
    return f"{offset:08X}│HView-Linux"


# These writers place controlled little-endian fields into the PE fixture buffer.
def put16(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", data, offset, value)


def put32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def put64(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", data, offset, value)


# This builder creates one bounded PE32 or PE32+ image with controlled tables.
# The returned runtime base lets later checks calculate exact mapped addresses.
def pe_fixture(plus: bool) -> tuple[bytes, int]:
    """Create one checked PE fixture with imports, exports, and overlay bytes."""
    # This section builds the DOS, COFF, and optional headers for the selected PE width.
    data = bytearray(0x810)
    data[:2] = b"MZ"
    put32(data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    put16(data, 0x84, 0x8664 if plus else 0x14C)
    put16(data, 0x86, 1)
    optional = 0x98
    optional_size = 0xF0 if plus else 0xE0
    put16(data, 0x94, optional_size)
    put16(data, optional, 0x20B if plus else 0x10B)
    put32(data, optional + 16, 0x1000)
    base = 0x140000000 if plus else 0x400000
    if plus:
        put64(data, optional + 24, base)
    else:
        put32(data, optional + 28, base)
    put32(data, optional + 32, 0x1000)
    put32(data, optional + 36, 0x200)
    put32(data, optional + 56, 0x2000)
    put32(data, optional + 60, 0x200)
    put32(data, optional + (108 if plus else 92), 16)

    # This section maps the export, import, and security directories to controlled fixture ranges.
    directories = optional + (112 if plus else 96)
    put32(data, directories, 0x1100)
    put32(data, directories + 4, 0xA0)
    put32(data, directories + 8, 0x1000)
    put32(data, directories + 12, 0x28)
    put32(data, directories + 32, 0x808)
    put32(data, directories + 36, 8)

    # This section defines one readable section that maps runtime addresses to bounded file bytes.
    section = optional + optional_size
    data[section : section + 8] = b".rdata\0\0"
    put32(data, section + 8, 0x600)
    put32(data, section + 12, 0x1000)
    put32(data, section + 16, 0x600)
    put32(data, section + 20, 0x200)
    put32(data, section + 36, 0x40000040)

    # This section builds import descriptors, lookup entries, names, and ordinal imports for both widths.
    put32(data, 0x200, 0x1040)
    put32(data, 0x20C, 0x1080)
    put32(data, 0x210, 0x1060)
    if plus:
        put64(data, 0x240, 0x1090)
        put64(data, 0x248, 1 << 63 | 7)
        put64(data, 0x260, 0x1090)
        put64(data, 0x268, 1 << 63 | 7)
    else:
        put32(data, 0x240, 0x1090)
        put32(data, 0x244, 1 << 31 | 7)
        put32(data, 0x260, 0x1090)
        put32(data, 0x264, 1 << 31 | 7)
    data[0x280:0x28D] = b"KERNEL32.dll\0"
    put16(data, 0x290, 0x1234)
    data[0x292:0x29E] = b"ExitProcess\0"

    # This section builds export tables, names, a forwarder, and a final certificate overlay marker.
    put32(data, 0x30C, 0x1140)
    put32(data, 0x310, 1)
    put32(data, 0x314, 3)
    put32(data, 0x318, 2)
    put32(data, 0x31C, 0x1128)
    put32(data, 0x320, 0x1134)
    put32(data, 0x324, 0x113C)
    put32(data, 0x328, 0x1170)
    put32(data, 0x32C, 0x1010)
    put32(data, 0x330, 0x1020)
    put32(data, 0x334, 0x1150)
    put32(data, 0x338, 0x1160)
    put16(data, 0x33C, 0)
    put16(data, 0x33E, 1)
    data[0x340:0x34C] = b"fixture.dll\0"
    data[0x350:0x35A] = b"Forwarded\0"
    data[0x360:0x366] = b"Named\0"
    data[0x370:0x37D] = b"OTHER.Target\0"
    data[0x800:0x810] = b"TAILCERTIFICATE!"

    # These final checks connect mapped fields to the expected runtime values returned with the bytes.
    assert 0x1000 + 0x210 - 0x200 == 0x1010
    assert base + 0x1010 in (0x401010, 0x140001010)
    return bytes(data), base


# This check drives exact and wildcard searches through Alt+F, Alt+R, and Alt+B.
# Selected-offset headers confirm search positions in both directions.
def check_search(binary: Path, root: Path) -> None:
    """Check exact and masked search directions."""
    exact = root / "exact.bin"
    data = bytearray(b"." * 0x80)
    for offset in (0x10, 0x30, 0x50):
        data[offset : offset + 6] = b"TARGET"
    exact.write_bytes(data)
    output = run_session(
        binary,
        ["/Ot=0", str(exact)],
        [ALT_F, b"TARGET", ENTER, ALT_R, ALT_B, CTRL_Q],
    )
    require_count(output, header(0x10), 2)
    require(output, header(0x30))

    masked = root / "masked.bin"
    data = bytearray(0x60)
    data[0x18:0x1A] = b"\xAB\x3F"
    data[0x38:0x3A] = b"\xA1\xFF"
    masked.write_bytes(data)
    output = run_session(
        binary,
        ["/Oh=0", str(masked)],
        [ALT_F, b"A? ?F", ENTER, ALT_R, ALT_B, ALT_F, b"A", ENTER, ENTER, CTRL_Q],
    )
    require_count(output, header(0x18), 2)
    require(output, header(0x38), "Enter complete hex byte pairs. Use ? for a wildcard nibble.")


# This check opens each bounded inspector and verifies its selected byte-order output.
def check_inspection(binary: Path, root: Path) -> None:
    """Check strings, integers, and browser selection."""
    path = root / "inspection.bin"
    data = bytearray(0x100)
    data[:8] = b"\xFF\x80\0\0\0\0\0\0"
    data[0x20:0x29] = b"plainText"
    data[0x1F] = data[0x29] = 0xFF
    data[0x40:0x48] = b"W\0I\0D\0E\0"
    data[0x3F] = data[0x48] = 0xFF
    data[0x60:0x68] = b"\0B\0E\0A\0M"
    data[0x5F] = data[0x68] = 0xFF
    path.write_bytes(data)
    output = run_session(
        binary,
        ["/Oh=0", str(path)],
        [CTRL_T, b"i", ESC, CTRL_T, b"s", DOWN, ENTER, CTRL_T, b"i", ESC, CTRL_Q],
    )
    require(
        output,
        "8-bit: unsigned 255, signed -1, hex FF",
        "16-bit BE: unsigned 65408, signed -128, hex FF80",
        "ASCII: plainText",
        "UTF-16LE: WIDE",
        "UTF-16BE: BEAM",
        header(0x40),
        "8-bit: unsigned 87, signed 87, hex 57",
    )


# This check supplies controlled low-entropy and high-entropy blocks to the entropy worker and browser.
# The initial progress frame proves the release application uses the connected worker route.
def check_entropy(binary: Path, root: Path) -> None:
    """Check entropy values and browser paging."""
    path = root / "entropy.bin"
    blocks = [bytes(4096), bytes(range(256)) * 16]
    blocks.extend(bytes([value]) * 4096 for value in range(2, 22))
    path.write_bytes(b"".join(blocks))
    output = run_session(
        binary,
        ["/Oh=0", str(path)],
        [CTRL_T, b"e", PAGE_DOWN, ENTER, CTRL_Q],
    )
    require(
        output,
        "Entropy... Working",
        "4096 bytes  0.000 bits/byte  [................]",
        "4096 bytes  8.000 bits/byte  [################]",
        "> 00014000",
        header(0x14000),
    )


# This check compares unsaved bytes and verifies that Escape preserves active edit state.
def check_compare_and_cancel(binary: Path, root: Path) -> None:
    """Check comparison against the unsaved buffer and edit cancellation."""
    current = root / "current.bin"
    other = root / "other.bin"
    original = bytes(0x100)
    current.write_bytes(original)
    changed = bytearray(original)
    changed[0x80] = 0xCC
    other.write_bytes(changed)
    output = run_session(
        binary,
        ["/Oh=10", str(current)],
        [ALT_E, b"FF", CTRL_T, b"d", str(other).encode(), ENTER, DOWN, ENTER, ESC, CTRL_Q],
    )
    require(
        output,
        "Compare... Working",
        "1 byte: old [FF], new [00]",
        "1 byte: old [00], new [CC]",
        header(0x80),
    )
    if current.read_bytes() != original:
        raise AssertionError("Edit cancellation changed the comparison file.")


# These checks reject a FIFO without a writer and accept two large sparse regular peers.
# Undo, redo, and edit cancellation must preserve the current file after each worker result.
def check_compare_sources(binary: Path, root: Path) -> None:
    """Check guarded peer opening, sparse lengths, and current edit state."""
    current = root / "guarded-current.bin"
    original = bytes(0x100)
    current.write_bytes(original)
    fifo = root / "compare.fifo"
    os.mkfifo(fifo, 0o600)

    # The FIFO has no writer, so the regular-file guard must return before terminal input stops.
    # A later empty comparison after undo proves that the failed worker kept the edit history.
    output = run_session(
        binary,
        ["/Oh=0", str(current)],
        [
            ALT_E, b"FF", CTRL_T, b"d", fifo.name.encode(), ENTER, ENTER,
            CTRL_Z, CTRL_T, b"d", current.name.encode(), ENTER, ESC,
            CTRL_Y, CTRL_T, b"d", current.name.encode(), ENTER, ESC, ESC, CTRL_Q,
        ],
    )
    require(output, "Compare... Working", "The source is not a regular file.", "No results.", "1 byte: old [FF], new [00]")
    if current.read_bytes() != original:
        raise AssertionError("FIFO comparison changed the current file.")

    # Sparse tails exceed 64 MiB and 4 GiB while the child has only 96 MiB of address space.
    # Exact length and eight preview bytes prove that comparison accepts the complete peer length.
    for length in (128 * 1024 * 1024 + 17, (1 << 32) + 17):
        peer = root / f"compare-{length}.bin"
        with peer.open("wb") as file:
            file.write(original)
            file.write(b"abcdefgh")
            file.truncate(length)
        output = run_session(
            binary,
            ["/Oh=0", str(current)],
            [
                (128, 24), ALT_E, b"FF", CTRL_T, b"d", peer.name.encode(), ENTER, ESC,
                CTRL_Z, CTRL_T, b"i", ESC, CTRL_Y, ESC, CTRL_Q,
            ],
            address_limit_bytes=96 * 1024 * 1024,
        )
        require(
            output,
            "Compare... Working",
            "1 byte: old [FF], new [00]",
            f"{length - len(original)} bytes: old [<absent>], new [61 62 63 64 65 66 67 68 ...]",
            "8-bit: unsigned 0, signed 0, hex 00",
        )
        if current.read_bytes() != original or peer.stat().st_size != length:
            raise AssertionError("Sparse comparison changed a source file.")


# This check queues Escape with prompt completion while a large common range enters the worker.
# Following physical keys verify cancellation, active bytes, undo, redo, and terminal restoration.
def check_compare_worker_cancel(binary: Path, root: Path) -> None:
    """Check Compare cancellation without a partial browser or changed edit state."""
    current = root / "cancel-current.bin"
    peer = root / "cancel-peer.bin"
    length = 64 * 1024 * 1024
    with current.open("wb") as file:
        file.truncate(length)
    with peer.open("wb") as file:
        file.truncate(128 * 1024 * 1024 + 17)

    # Separate actions leave the Escape continuation interval empty before the next menu key arrives.
    # Left returns the cursor to the edited byte before comparison checks its preserved position.
    # Current unsaved FF bytes must remain visible before undo restores the original zero byte.
    output = run_session(
        binary,
        ["/Oh=0", str(current)],
        [
            ALT_E, b"FF", LEFT, CTRL_T, b"d", peer.name.encode(),
            ENTER + ESC, CTRL_T + b"i", ESC, CTRL_Z, CTRL_T, b"i", ESC,
            CTRL_Y, ESC, CTRL_Q,
        ],
        address_limit_bytes=384 * 1024 * 1024,
    )
    require(output, "Compare... Working", "00000000  8-bit: unsigned 255, signed -1, hex FF", "00000000  8-bit: unsigned 0, signed 0, hex 00")
    if b"Compare | buffer -> file" in output:
        raise AssertionError("Canceled comparison opened a partial result browser.")
    with current.open("rb") as file:
        if file.read(32) != bytes(32) or current.stat().st_size != length:
            raise AssertionError("Compare cancellation changed the current file.")


# This check applies Fill and XOR ranges through Editor history, then saves accepted bytes.
# Rejected and canceled inputs must keep the prior buffer and file state.
def check_ranges(binary: Path, root: Path) -> None:
    """Check XOR, fill, edit requirements, and rejected ranges."""
    path = root / "ranges.bin"
    path.write_bytes(bytes(range(0x00, 0x80, 0x11)))
    output = run_session(
        binary,
        ["/Oh=0", str(path)],
        [
            ALT_E,
            CTRL_T,
            b"x",
            b"0 4",
            ENTER,
            b"FF 0F",
            ENTER,
            CTRL_T,
            b"f",
            b"4 4",
            ENTER,
            b"AA 55",
            ENTER,
            ALT_S,
            CTRL_Q,
        ],
    )
    if output.count(b"EDITMODE") < 2:
        raise AssertionError("The range workflow did not remain in edit mode.")
    expected = bytes.fromhex("FF 1E DD 3C AA 55 AA 55")
    if path.read_bytes() != expected:
        raise AssertionError("The saved XOR and fill bytes are incorrect.")

    rejected = root / "rejected-range.bin"
    original = bytes(range(8))
    rejected.write_bytes(original)
    output = run_session(
        binary,
        ["/Oh=0", str(rejected)],
        [CTRL_T, b"x", ENTER, ALT_E, CTRL_T, b"x", b"7 2", ENTER, b"FF", ENTER, ENTER, ESC, CTRL_Q],
    )
    require(output, "Press Alt+E to enter edit mode first.", "The block extends past the file end.")
    if rejected.read_bytes() != original:
        raise AssertionError("A rejected range changed the file.")


# This check browses controlled PE structures and requires their mapped file rows.
def check_structures(binary: Path, path: Path) -> None:
    """Check PE structure rows, horizontal movement, and cancellation."""
    before = path.read_bytes()
    output = run_session(
        binary,
        ["/Oh=210", str(path)],
        [CTRL_T, b"p", RIGHT, RIGHT, RIGHT, RIGHT, ESC, CTRL_Q],
    )
    require(
        output,
        "Section .rdata | File=00000200 RVA=00001000",
        "Directory Export | File=00000300 RVA=00001100",
        "Directory Import | File=00000200 RVA=00001000",
        "Directory Security | File=00000808 RVA=- VA=-",
        "Import KERNEL32.dll!ExitProcess Hint=1234",
        "Import KERNEL32.dll!#7",
        "Export fixture.dll!Forwarded",
        "Export fixture.dll!Named",
        "Export fixture.dll!#3",
        "Forwarder=OTHER.Target",
        "Overlay | File=00000800 RVA=- VA=- Size=00000010",
    )
    require_count(output, header(0x210), 2)
    if path.read_bytes() != before:
        raise AssertionError("PE browser cancellation changed the file.")


# This check converts PE32 file, RVA, and VA values and verifies rejected addresses.
def check_pe32_addresses(binary: Path, path: Path) -> None:
    """Check PE32 addresses against current and restored image bases."""
    before = path.read_bytes()
    output = run_session(
        binary,
        ["/Oh=B6", str(path)],
        [
            ALT_E,
            b"50",
            CTRL_T,
            b"a",
            b"F 210",
            ENTER,
            ESC,
            ESC,
            CTRL_T,
            b"a",
            b"F 210",
            ENTER,
            ENTER,
            CTRL_T,
            b"a",
            b"R 1010",
            ENTER,
            ESC,
            CTRL_T,
            b"a",
            b"V 401010",
            ENTER,
            ESC,
            CTRL_T,
            b"a",
            b"R 1600",
            ENTER,
            ENTER,
            CTRL_Q,
        ],
    )
    require(
        output,
        "File=00000210 RVA=00001010 VA=0000000000501010",
        "File=00000210 RVA=00001010 VA=0000000000401010",
        header(0x210),
        "outside the PE image",
    )
    require_count(output, "File=00000210 RVA=00001010 VA=0000000000401010", 3)
    if path.read_bytes() != before:
        raise AssertionError("PE edit cancellation changed the file.")


# This check repeats address conversion at PE32+ width with a 64-bit image base.
def check_pe32_plus_addresses(binary: Path, path: Path) -> None:
    """Check PE32+ file, RVA, and preferred-base VA conversion."""
    output = run_session(
        binary,
        ["/Oh=0", str(path)],
        [
            CTRL_T,
            b"a",
            b"F 210",
            ENTER,
            ENTER,
            CTRL_T,
            b"a",
            b"R 1010",
            ENTER,
            ESC,
            CTRL_T,
            b"a",
            b"V 140001010",
            ENTER,
            ESC,
            CTRL_T,
            b"a",
            b"R 1600",
            ENTER,
            ENTER,
            CTRL_Q,
        ],
    )
    expected = "File=00000210 RVA=00001010 VA=0000000140001010"
    require(output, expected, header(0x210), "outside the PE image")
    require_count(output, expected, 3)


# This entry point builds all disposable fixtures and runs each analysis control group.
# A successful result means every child session also restored its terminal.
def main() -> None:
    """Run the analysis checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: analysis_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")
    with tempfile.TemporaryDirectory(prefix="hview-analysis-") as temporary:
        root = Path(temporary)
        check_search(binary, root)
        check_inspection(binary, root)
        check_entropy(binary, root)
        check_compare_and_cancel(binary, root)

        # Short prompt paths keep the key sequence behind completed prompt redraws.
        # Restore the caller directory before later checks use their existing absolute paths.
        previous = Path.cwd()
        try:
            os.chdir(root)
            check_compare_sources(binary, root)
            check_compare_worker_cancel(binary, root)
        finally:
            os.chdir(previous)
        check_ranges(binary, root)

        pe32 = root / "fixture-pe32.bin"
        pe32_plus = root / "fixture-pe32-plus.bin"
        pe32_data, pe32_base = pe_fixture(False)
        pe32_plus_data, pe32_plus_base = pe_fixture(True)
        assert pe32_base == 0x400000
        assert pe32_plus_base == 0x140000000
        pe32.write_bytes(pe32_data)
        pe32_plus.write_bytes(pe32_plus_data)
        check_structures(binary, pe32)
        check_structures(binary, pe32_plus)
        check_pe32_addresses(binary, pe32)
        check_pe32_plus_addresses(binary, pe32_plus)
    print("Analysis probe passed.")


if __name__ == "__main__":
    main()
