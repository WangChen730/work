import hashlib
import itertools


TARGET_SHA1 = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

# Visible traces on the German keyboard suggest these physical keys.
# For symbol keys we include the unshifted and shifted characters.
KEY_CHOICES = {
    "Q": ["q", "Q"],
    "W": ["w", "W"],
    "I": ["i", "I"],
    "N": ["n", "N"],
    "5": ["5", "%"],
    "8": ["8", "("],
    "0": ["0", "="],
    "+": ["+", "*"],
}


def crack_password(target_sha1: str) -> str | None:
    keys = list(KEY_CHOICES)
    for perm in itertools.permutations(keys):
        pools = [KEY_CHOICES[key] for key in perm]
        for chars in itertools.product(*pools):
            candidate = "".join(chars)
            digest = hashlib.sha1(candidate.encode()).hexdigest()
            if digest == target_sha1:
                return candidate
    return None


def main() -> None:
    password = crack_password(TARGET_SHA1)
    if password is None:
        print("No password found.")
        return

    print(f"Password: {password}")
    print(f"SHA1: {hashlib.sha1(password.encode()).hexdigest()}")


if __name__ == "__main__":
    main()
