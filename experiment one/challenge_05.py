from cryptopals_set1 import bytes_to_hex, repeating_key_xor
def main() -> None:
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    expected = (
        "0b3637272a2b2e63622c2e69692a2369"
        "3a2a3c6324202d623d63343c2a262263"
        "24272765272a282b2f20430a652e2c65"
        "2a3124333a653e2b2027630c692b2028"
        "3165286326302e27282f"
    )
    ciphertext = repeating_key_xor(plaintext, key)
    result = bytes_to_hex(ciphertext)
    assert result == expected
    print(result)
if __name__ == "__main__":
    main()
