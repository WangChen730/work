import base64

from cryptopals_set1 import break_repeating_key_xor, hamming_distance, load_or_download_text
INPUT_URL = "https://cryptopals.com/static/challenge-data/6.txt"
def main() -> None:
    assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37
    raw_text = load_or_download_text("6.txt", INPUT_URL)
    ciphertext = base64.b64decode(raw_text)
    result = break_repeating_key_xor(ciphertext, top_key_sizes=12)
    key = result["key"].decode("ascii")
    plaintext = result["plaintext"].decode("utf-8", errors="replace")
    assert key == "Terminator X: Bring the noise"
    print(f"key={key}")
    print(plaintext[:500])
if __name__ == "__main__":
    main()
