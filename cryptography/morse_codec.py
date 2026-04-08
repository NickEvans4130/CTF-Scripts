#!/usr/bin/env python3
"""
Morse code encoder and decoder.
Supports . - and * - delimiter variants and custom word gaps.
"""

import argparse
import sys

MORSE_TO_CHAR = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", ".----.": "'",
    "-.-.--": "!", "-..-.": "/", "-.--.": "(", "-.--.-": ")",
    ".-...": "&", "---...": ":", "-.-.-.": ";", "-...-": "=",
    ".-.-.": "+", "-....-": "-", "..--.-": "_", ".-..-.": '"',
    "...-..-": "$", ".--.-.": "@",
}
CHAR_TO_MORSE = {v: k for k, v in MORSE_TO_CHAR.items()}


def normalise(text: str) -> str:
    """Normalise * to . for decoding."""
    return text.replace('*', '.')


def decode(morse: str, word_delim: str = " / ") -> str:
    morse = normalise(morse)
    result = []
    words = morse.split(word_delim) if word_delim in morse else [morse]
    for word in words:
        letters = word.strip().split()
        decoded_word = []
        for code in letters:
            decoded_word.append(MORSE_TO_CHAR.get(code, f'[{code}]'))
        result.append(''.join(decoded_word))
    return ' '.join(result)


def encode(text: str, dot: str = '.', dash: str = '-',
           letter_sep: str = ' ', word_sep: str = ' / ') -> str:
    result = []
    for word in text.upper().split():
        coded_word = []
        for char in word:
            code = CHAR_TO_MORSE.get(char)
            if code:
                coded_word.append(code.replace('.', dot).replace('-', dash))
            elif char == ' ':
                pass
            else:
                coded_word.append(f'[{char}]')
        result.append(letter_sep.join(coded_word))
    return word_sep.join(result)


def main():
    parser = argparse.ArgumentParser(description="Morse code encoder / decoder")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--encode", "-e", metavar="TEXT", help="Text to encode to Morse")
    mode.add_argument("--decode", "-d", metavar="MORSE", help="Morse to decode to text")

    parser.add_argument("--delim", default=" / ",
                        help="Word delimiter in Morse input/output (default: ' / ')")
    parser.add_argument("--dot",  default=".",
                        help="Character to use for dot in output (default: '.')")
    parser.add_argument("--dash", default="-",
                        help="Character to use for dash in output (default: '-')")
    args = parser.parse_args()

    if args.encode:
        result = encode(args.encode, dot=args.dot, dash=args.dash, word_sep=args.delim)
        print(result)
    else:
        result = decode(args.decode, word_delim=args.delim)
        print(result)


if __name__ == "__main__":
    main()
