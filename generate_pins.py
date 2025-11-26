"""Generate unique PINs of various lengths using strong randomness.

This script supports generating 4-, 6-, and 8-digit PINs with a more
complex randomization approach that hashes cryptographically secure
random bytes. An optional information flag explains the program rules.
"""
from __future__ import annotations

import argparse
import hashlib
import secrets
from datetime import datetime
from typing import Iterable, List, Set


def _complex_random_digits(length: int) -> str:
    """Return a zero-padded string of digits using hashed random bytes.

    A SHA3-512 digest of 64 random bytes is converted to an integer and
    reduced modulo the required range. This avoids predictable patterns
    while keeping digits only.
    """

    if length <= 0:
        raise ValueError("Length must be positive")

    random_bytes = secrets.token_bytes(64)
    digest = hashlib.sha3_512(random_bytes).digest()
    random_number = int.from_bytes(digest, "big")
    pin_int = random_number % (10 ** length)
    return f"{pin_int:0{length}d}"


def _generate_unique_pins(length: int, count: int) -> List[str]:
    """Generate a list of unique PINs of a specific length."""
    if count < 0:
        raise ValueError("Count cannot be negative")

    pins: Set[str] = set()
    max_unique = 10 ** length
    if count > max_unique:
        raise ValueError(
            f"Cannot generate {count} unique PINs of length {length}; "
            f"maximum is {max_unique}."
        )

    while len(pins) < count:
        pins.add(_complex_random_digits(length))
    return sorted(pins)


def _write_output(file_path: str, pins_by_length: Iterable[tuple[int, List[str]]]) -> None:
    """Write generated PINs to a text file with headers."""
    timestamp = datetime.now().isoformat(timespec="seconds")
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(f"PIN generation time: {timestamp}\n")
        for length, pins in pins_by_length:
            file.write(f"\n{length}-digit PINs:\n")
            for pin in pins:
                file.write(f"{pin}\n")


def _print_rules() -> None:
    """Display program rules and guidance."""
    rules = """
Program rules
-------------
1) Generates only numeric PINs in three lengths: 4, 6, and 8 digits.
2) Each PIN is unique within its length group for a single run.
3) Randomness is derived from SHA3-512 hashing of 64 cryptographically
   secure random bytes, avoiding simple sequential patterns.
4) Output is written to a text file, grouped by PIN length with headers.
5) You can customize how many PINs to create per length and the output
   file location using command-line options.
"""
    print(rules.strip())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate unique 4-, 6-, and 8-digit PINs using strong randomness.",
    )
    parser.add_argument(
        "--count4", type=int, default=10, help="Number of 4-digit PINs to generate (default: 10)",
    )
    parser.add_argument(
        "--count6", type=int, default=10, help="Number of 6-digit PINs to generate (default: 10)",
    )
    parser.add_argument(
        "--count8", type=int, default=10, help="Number of 8-digit PINs to generate (default: 10)",
    )
    parser.add_argument(
        "--output",
        default="pins.txt",
        help="Path to the output text file (default: pins.txt)",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show program rules and exit",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.info:
        _print_rules()
        return

    pins4 = _generate_unique_pins(4, args.count4)
    pins6 = _generate_unique_pins(6, args.count6)
    pins8 = _generate_unique_pins(8, args.count8)

    _write_output(
        args.output,
        ((4, pins4), (6, pins6), (8, pins8)),
    )

    print(
        "Generated PINs with complex randomization and saved to",
        args.output,
    )


if __name__ == "__main__":
    main()
