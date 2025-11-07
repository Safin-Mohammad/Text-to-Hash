#!/usr/bin/env python3
import hashlib
import os
import sys
import argparse
from typing import Callable, Dict

RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[1;34m"
RESET = "\033[0m"

BANNER = r"""
       _____         _     _        
      |_   _|       | |   | |       
        | | _____  _| |_  | |_ ___  
        | |/ _ \ \/ / __| | __/ _ \ 
        | |  __/>  <| |_  | || (_) |
        \_/\___/_/\_\\__|  \__\___/ 
                                                      
                             _   _   ___   _____ _   _ 
                            | | | | / _ \ /  ___| | | |
                            | |_| |/ /_\ \\ `--.| |_| |
                            |  _  ||  _  | `--. \  _  |
                            | | | || | | |/\__/ / | | |
                            \_| |_/\_| |_/\____/\_| |_/
"""

ALGORITHMS: Dict[str, Callable[[], "hashlib._Hash"]] = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}

CHOICES = {
    "1": "md5",
    "2": "sha1",
    "3": "sha224",
    "4": "sha256",
    "5": "sha384",
    "6": "sha512",
    "7": "sha3_224",
    "8": "sha3_256",
    "9": "sha3_384",
    "10": "sha3_512",
    "11": "blake2b",
    "12": "blake2s",
}


def clear_screen():
    # cross-platform clear
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    print("_" * 67)
    print(BANNER)
    print("\ncreated by SAFIN MOHAMMAD")
    print("_" * 67)


def pick_algorithm_interactive() -> str:
    print("\nAvailable hash algorithms:")
    for num, name in CHOICES.items():
        print(f"[{num}] {name}")
    choice = input("[+] Choose algorithm (number): ").strip()
    algo_name = CHOICES.get(choice)
    if not algo_name:
        print(f"{RED}[-] Invalid algorithm choice{RESET}")
        sys.exit(1)
    return algo_name


def hash_string(s: str, algo_name: str) -> str:
    ctor = ALGORITHMS[algo_name]
    h = ctor()
    h.update(s.encode("utf-8"))
    return h.hexdigest()


def convert_single_word_interactive():
    passwd = input("[+] Enter text to hash: ").rstrip("\n")
    if passwd == "":
        print(f"{RED}[-] Empty input{RESET}")
        return
    algo_name = pick_algorithm_interactive()
    print(f"{GREEN}{hash_string(passwd, algo_name)}{RESET}")


def convert_file(input_path: str, algo_name: str, output_path: str = None):
    if algo_name not in ALGORITHMS:
        print(f"{RED}[-] Unknown algorithm: {algo_name}{RESET}")
        sys.exit(1)

    try:
        with open(input_path, "r", errors="replace") as fin:
            lines = fin.readlines()
    except FileNotFoundError:
        print(f"{RED}[-] File not found: {input_path}{RESET}")
        sys.exit(1)

    count = 0
    out_lines = []
    for line in lines:
        password = line.strip()
        if password == "":
            continue
        hashed = hash_string(password, algo_name)
        out_lines.append(hashed)
        print(hashed)
        count += 1

    print(f"{GREEN}[+] {count} lines converted into {algo_name}{RESET}")

    if output_path:
        try:
            with open(output_path, "w") as fout:
                fout.write("\n".join(out_lines) + ("\n" if out_lines else ""))
            print(f"{GREEN}[+] Saved hashes to {output_path}{RESET}")
        except OSError as e:
            print(f"{RED}[-] Failed to write output file: {e}{RESET}")


def interactive_mode():
    print("""
[1] I want to convert single word into hash
[2] I want to convert hashes from a txt file
""")
    optn = input("[+] choose any one : ").strip()
    if optn == "1":
        convert_single_word_interactive()
    elif optn == "2":
        f = input("[+] Enter your target txt file : ").strip()
        if f == "":
            print(f"{RED}[-] No file provided{RESET}")
            return
        algo_name = pick_algorithm_interactive()
        convert_file(f, algo_name)
    else:
        print(f"{RED}[-] Invalid choice !{RESET}")


def parse_args():
    parser = argparse.ArgumentParser(description="Hash converter utility")
    parser.add_argument("-s", "--string", help="Single string to hash (non-interactive)")
    parser.add_argument("-i", "--input", help="Input file with strings (one per line)")
    parser.add_argument("-o", "--output", help="Output file to write hashes to (optional)")
    parser.add_argument(
        "-a",
        "--algorithm",
        choices=list(ALGORITHMS.keys()),
        help="Hash algorithm to use (non-interactive). If omitted in interactive mode you'll be prompted.",
    )
    parser.add_argument("--no-clear", action="store_true", help="Don't clear the terminal on start")
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.no_clear:
        clear_screen()
    print_banner()

    # Non-interactive modes
    if args.string:
        if not args.algorithm:
            print(f"{RED}[-] When using --string you must supply --algorithm{RESET}")
            sys.exit(1)
        print(hash_string(args.string, args.algorithm))
        return

    if args.input:
        algo = args.algorithm
        if not algo:
            # fall back to interactive algorithm selection
            algo = pick_algorithm_interactive()
        convert_file(args.input, algo, args.output)
        return

    # default: interactive menu
    interactive_mode()


if __name__ == "__main__":
    main()
