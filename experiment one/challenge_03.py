from cryptopals_set1 import crack_single_byte_xor, hex_to_bytes
def main() -> None:
    ciphertext = hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    result = crack_single_byte_xor(ciphertext)
    plaintext = result["plaintext"].decode("ascii")
    key = chr(int(result["key"]))
    assert plaintext == "Cooking MC's like a pound of bacon"
    print(f"key={key}")
    print(plaintext)
if __name__ == "__main__":
    main()
