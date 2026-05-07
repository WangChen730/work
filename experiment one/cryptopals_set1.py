from __future__ import annotations

import base64
import binascii
import urllib.request
from itertools import combinations
from pathlib import Path


def hex_to_bytes(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string.strip())


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def fixed_xor(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("fixed_xor requires buffers of equal length")
    return bytes(a ^ b for a, b in zip(left, right))


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def hamming_distance(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("hamming_distance requires buffers of equal length")
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def english_score(data: bytes) -> float:
    frequent = "ETAOIN SHRDLUetaoinshrdlu"
    punctuation = ".,'\"!?;:-()"
    score = 0.0

    for byte in data:
        char = chr(byte)
        if char in frequent:
            score += 2.0
        elif char.isalpha():
            score += 1.0
        elif char == " ":
            score += 1.5
        elif char.isdigit():
            score += 0.2
        elif char in punctuation:
            score += 0.3
        elif byte in (9, 10, 13):
            score += 0.0
        elif 32 <= byte <= 126:
            score -= 0.1
        else:
            score -= 5.0

    return score


def crack_single_byte_xor(ciphertext: bytes) -> dict[str, object]:
    best: dict[str, object] | None = None

    for key in range(256):
        plaintext = bytes(byte ^ key for byte in ciphertext)
        score = english_score(plaintext)
        candidate = {"key": key, "plaintext": plaintext, "score": score}
        if best is None or score > float(best["score"]):
            best = candidate

    assert best is not None
    return best


def guess_key_sizes(ciphertext: bytes, minimum: int = 2, maximum: int = 40, top: int = 10) -> list[int]:
    candidates: list[tuple[float, int]] = []

    for key_size in range(minimum, maximum + 1):
        chunks = [ciphertext[index:index + key_size] for index in range(0, key_size * 6, key_size)]
        chunks = [chunk for chunk in chunks if len(chunk) == key_size]
        if len(chunks) < 4:
            continue

        distances = [
            hamming_distance(left, right) / key_size
            for left, right in combinations(chunks, 2)
        ]

        average = sum(distances) / len(distances)
        candidates.append((average, key_size))

    candidates.sort()
    return [key_size for _, key_size in candidates[:top]]


def break_repeating_key_xor(ciphertext: bytes, top_key_sizes: int = 10) -> dict[str, object]:
    best: dict[str, object] | None = None

    for key_size in guess_key_sizes(ciphertext, top=top_key_sizes):
        key_bytes = bytearray()
        for column_index in range(key_size):
            block = ciphertext[column_index::key_size]
            result = crack_single_byte_xor(block)
            key_bytes.append(int(result["key"]))

        key = bytes(key_bytes)
        plaintext = repeating_key_xor(ciphertext, key)
        score = english_score(plaintext)
        candidate = {
            "key_size": key_size,
            "key": key,
            "plaintext": plaintext,
            "score": score,
        }
        if best is None or score > float(best["score"]):
            best = candidate

    assert best is not None
    return best


def load_or_download_text(filename: str, url: str) -> str:
    path = Path(__file__).with_name("inputs") / filename
    if path.exists():
        return path.read_text(encoding="ascii")

    path.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "cryptopals-set1-solver"})

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read()
    except Exception as exc:
        raise FileNotFoundError(
            f"Missing input file: {path}\n"
            f"Place the official file there or download it from: {url}"
        ) from exc

    path.write_bytes(data)
    return data.decode("ascii")


def decode_hex_line(line: str) -> bytes:
    try:
        return binascii.unhexlify(line.strip())
    except binascii.Error as exc:
        raise ValueError(f"Invalid hex line: {line[:32]!r}") from exc
