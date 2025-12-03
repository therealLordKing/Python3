"""Utility to identify a file's real type using binary magic numbers.

The script reads the leading bytes from each provided file, compares them to
common file signatures, and reports whether the file extension aligns with the
actual content. It is intentionally small and self contained so it can be used
from the command line or imported into other scripts.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# A mapping of human-readable file types to one or more magic number prefixes.
MAGIC_DATABASE: Dict[str, List[bytes]] = {
    "JPEG": [b"\xFF\xD8\xFF"],
    "PNG": [b"\x89PNG\r\n\x1A\n"],
    "GIF": [b"GIF87a", b"GIF89a"],
    "PDF": [b"%PDF-"],
    "ZIP": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "GZIP": [b"\x1F\x8B\x08"],
    "RAR": [b"Rar!\x1A\x07\x00", b"Rar!\x1A\x07\x01\x00"],
    "7Z": [b"7z\xBC\xAF\x27\x1C"],
    "BMP": [b"BM"],
    "EXE": [b"MZ"],
    "ELF": [b"\x7FELF"],
    "MP3": [b"ID3", b"\xFF\xFB"],
    "WAV": [b"RIFF"],
    "FLAC": [b"fLaC"],
    "MP4": [b"\x00\x00\x00"],  # Simplified; container checks vary.
}

# File extensions mapped to the expected type names above.
EXTENSION_MAP: Dict[str, str] = {
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".png": "PNG",
    ".gif": "GIF",
    ".pdf": "PDF",
    ".zip": "ZIP",
    ".gz": "GZIP",
    ".rar": "RAR",
    ".7z": "7Z",
    ".bmp": "BMP",
    ".exe": "EXE",
    ".dll": "EXE",
    ".elf": "ELF",
    ".mp3": "MP3",
    ".wav": "WAV",
    ".flac": "FLAC",
    ".mp4": "MP4",
}


def longest_magic_length(magic_db: Dict[str, List[bytes]]) -> int:
    """Return the length of the longest magic number in the database."""
    return max(len(pattern) for patterns in magic_db.values() for pattern in patterns)


def read_file_header(path: Path, byte_count: int) -> bytes:
    """Read the first ``byte_count`` bytes from ``path``.

    Parameters
    ----------
    path:
        The file to inspect.
    byte_count:
        Number of bytes to read, typically the length of the longest signature
        in the magic database.
    """
    with path.open("rb") as file_handle:
        return file_handle.read(byte_count)


def detect_file_type(header: bytes, magic_db: Dict[str, List[bytes]]) -> Optional[str]:
    """Return the detected file type from the header bytes.

    The function scans through the provided database and returns the first
    matching type whose magic number is a prefix of the header. ``None`` is
    returned when no match is found.
    """
    for type_name, patterns in magic_db.items():
        for pattern in patterns:
            if header.startswith(pattern):
                return type_name
    return None


def expected_type_from_extension(path: Path, extension_map: Dict[str, str]) -> Optional[str]:
    """Infer expected type from the file extension, if known."""
    return extension_map.get(path.suffix.lower())


def analyze_file(path: Path, magic_db: Dict[str, List[bytes]], extension_map: Dict[str, str]) -> Tuple[str, Optional[str], Optional[str]]:
    """Analyze a single file and return a tuple with status information.

    Returns
    -------
    tuple
        (file path as string, actual type or "Unknown", mismatch message or
        ``None`` when the extension matches the detected type).
    """
    max_length = longest_magic_length(magic_db)
    header = read_file_header(path, max_length)
    detected_type = detect_file_type(header, magic_db) or "Unknown"
    expected_type = expected_type_from_extension(path, extension_map)

    mismatch = None
    if expected_type and expected_type != detected_type:
        mismatch = (
            f"Extension suggests {expected_type}, but header indicates {detected_type}."
        )
    elif not expected_type:
        mismatch = "No known expected type for this extension." if detected_type != "Unknown" else None

    return detected_type, expected_type, mismatch


def list_known_types(magic_db: Dict[str, List[bytes]]) -> None:
    """Print the known types and their magic numbers."""
    print("Known magic numbers:\n")
    for type_name, patterns in sorted(magic_db.items()):
        hex_patterns = ", ".join(pattern.hex().upper() for pattern in patterns)
        print(f"- {type_name}: {hex_patterns}")


def main(arguments: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "files",
        metavar="FILE",
        nargs="*",
        type=Path,
        help="Path(s) to the files to inspect.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Show known file types and exit without scanning files.",
    )
    args = parser.parse_args(list(arguments) if arguments is not None else None)

    if args.list:
        list_known_types(MAGIC_DATABASE)
        return 0

    if not args.files:
        parser.error("no files supplied; provide one or more paths to inspect")

    mismatches: List[str] = []

    for file_path in args.files:
        if not file_path.exists():
            print(f"[ERROR] {file_path} does not exist.")
            continue
        detected_type, expected_type, mismatch = analyze_file(
            file_path, MAGIC_DATABASE, EXTENSION_MAP
        )
        print(f"\nFile: {file_path}")
        print(f"  Detected type: {detected_type}")
        if expected_type:
            print(f"  Extension expects: {expected_type}")
        else:
            print("  Extension expects: <unknown>")
        if mismatch:
            mismatches.append(f"{file_path}: {mismatch}")
            print(f"  MISMATCH: {mismatch}")
        else:
            print("  Status: extension matches detected type.")

    print("\nSummary:")
    if mismatches:
        for issue in mismatches:
            print(f"- {issue}")
    else:
        print("- All inspected files match their extensions or types are unknown.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
