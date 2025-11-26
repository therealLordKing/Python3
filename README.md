# Python3
Python3 code. Use this responsibly. I do not condone misuse. Don't add to the problem.

## PIN generator script
Use `generate_pins.py` to create unique 4-, 6-, and 8-digit PINs backed by a SHA3-512 hash of secure random bytes.

Examples:

- Show the program rules and how it works:
  ```bash
  python generate_pins.py --info
  ```
- Generate default sets of PINs into `pins.txt`:
  ```bash
  python generate_pins.py
  ```
- Customize how many PINs per length and where to store them:
  ```bash
  python generate_pins.py --count4 5 --count6 3 --count8 7 --output my_pins.txt
  ```

The script keeps PINs unique per length for each run and groups them in the output file with clear headers.
