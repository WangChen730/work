from cryptopals_set1 import crack_single_byte_xor, decode_hex_line, load_or_download_text
INPUT_URL = "https://cryptopals.com/static/challenge-data/4.txt"
def main() -> None:
    raw_text = load_or_download_text("4.txt", INPUT_URL)
    best = None
    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        result = crack_single_byte_xor(decode_hex_line(line))
        candidate = {
            "line_number": line_number,
            "key": int(result["key"]),
            "plaintext": result["plaintext"],
            "score": float(result["score"]),
        }
        if best is None or candidate["score"] > best["score"]:
            best = candidate
    assert best is not None
    plaintext = best["plaintext"].decode("ascii", errors="replace")
    assert plaintext.strip() == "Now that the party is jumping"
    print(f"line={best['line_number']}")
    print(f"key={chr(best['key'])}")
    print(plaintext)
if __name__ == "__main__":
    main()
