import unittest

import challenge10
import challenge11
import challenge12
import challenge13
import challenge14
import challenge15
import challenge16
import utils


class Set2Tests(unittest.TestCase):
    def test_utils_cbc_round_trip(self) -> None:
        key = b"YELLOW SUBMARINE"
        iv = bytes(utils.BLOCK_SIZE)
        message = b"CBC mode needs repeated blocks and padding." * 2
        ciphertext = utils.aes_cbc_encrypt(message, key, iv)
        plaintext = utils.aes_cbc_decrypt(ciphertext, key, iv, unpad=True)
        self.assertEqual(plaintext, message)

    def test_challenge_10(self) -> None:
        plaintext = challenge10.solve()
        self.assertTrue(plaintext.startswith(b"I'm back and I'm ringin' the bell"))

    def test_challenge_11(self) -> None:
        self.assertEqual(challenge11.solve(50), 50)

    def test_challenge_12(self) -> None:
        self.assertEqual(challenge12.solve(), challenge12.UNKNOWN_SUFFIX)

    def test_challenge_13(self) -> None:
        profile = challenge13.solve()
        self.assertEqual(profile["role"], "admin")

    def test_challenge_14(self) -> None:
        _, recovered = challenge14.solve()
        self.assertEqual(recovered, challenge14.UNKNOWN_SUFFIX)

    def test_challenge_15(self) -> None:
        self.assertEqual(challenge15.solve(), b"ICE ICE BABY")
        with self.assertRaises(ValueError):
            utils.pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05")
        with self.assertRaises(ValueError):
            utils.pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04")

    def test_challenge_16(self) -> None:
        self.assertTrue(challenge16.solve())


if __name__ == "__main__":
    unittest.main()
