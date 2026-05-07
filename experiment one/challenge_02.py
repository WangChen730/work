from cryptopals_set1 import bytes_to_hex, fixed_xor, hex_to_bytes
def main() -> None:
    left = hex_to_bytes("1c0111001f010100061a024b53535009181c")
    right = hex_to_bytes("686974207468652062756c6c277320657965")
    expected = "746865206b696420646f6e277420706c6179"
    result = bytes_to_hex(fixed_xor(left, right))
    assert result == expected
    print(result)
if __name__ == "__main__":
    main()
