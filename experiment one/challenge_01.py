from unittest import expectedFailure
from cryptopals_set1 import bytes_to_base64, hex_to_bytes
def main() -> None:
    source_hex = (
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573"
        "206d757368726f6f6d"
    )
    converted = bytes_to_base64(hex_to_bytes(source_hex))
    assert converted
    print(converted)
if __name__ == "__main__":
    main()
