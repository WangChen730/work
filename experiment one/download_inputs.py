from cryptopals_set1 import load_or_download_text


URLS = {
    "4.txt": "https://cryptopals.com/static/challenge-data/4.txt",
    "6.txt": "https://cryptopals.com/static/challenge-data/6.txt",
}


def main() -> None:
    for filename, url in URLS.items():
        load_or_download_text(filename, url)
        print(f"downloaded {filename}")


if __name__ == "__main__":
    main()
