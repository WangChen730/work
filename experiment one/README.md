# Cryptopals Set 1

This directory contains solutions for Cryptopals Set 1 challenges 1 through 6.

## Files

- `challenge_01.py` to `challenge_06.py`: one runnable script per challenge
- `solve_sha1_keyboard.py` :solve the problem of MTC3 Cracking SHA1-Hashed Passwords
- `cryptopals_set1.py`: shared helper functions
- `download_inputs.py`: downloads the official input files for challenges 4 and 6

## Run

```powershell
python .\challenge_01.py
python .\challenge_02.py
python .\challenge_03.py
python .\challenge_04.py
python .\challenge_05.py
python .\challenge_06.py
```

Challenges 4 and 6 need the official input files. Each script first reads from `inputs\`; if the file is missing, it tries to download and cache it automatically:

- `https://cryptopals.com/static/challenge-data/4.txt`
- `https://cryptopals.com/static/challenge-data/6.txt`

If your environment is offline, place those files in `inputs\` before running the scripts.
