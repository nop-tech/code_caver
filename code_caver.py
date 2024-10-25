# Built-in imports
import sys
import argparse

# Third party libraries
import pykd


PROTECTION_FLAGS = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
    0x100: "PAGE_GUARD",
    0x200: "PAGE_NOCACHE",
    0x400: "PAGE_WRITECOMBINE",
}


# Protection constants indicating executable memory
EXEC_PROTECTION_FLAGS = [
    0x10,  # PAGE_EXECUTE
    0x20,  # PAGE_EXECUTE_READ
    0x40,  # PAGE_EXECUTE_READWRITE
    0x80,  # PAGE_EXECUTE_WRITECOPY
]


def print_welcome_message():
    pykd.dprintln(
        """
==================================================
            Code Cave Scanner by nop
==================================================
        -> https://nop-blog.tech/
        -> https://github.com/nop-tech/
        -> https://twitter.com/thenopcode
==================================================
"""
    )


def get_module_range(module_name: str) -> tuple:
    """
    Retrieves the start and end addresses of a given module.
    """
    pykd.dprintln(f"[*] Searching for module '{module_name}' range")
    output = run(f"lm m {module_name}")
    if "start" in output and "end" in output:
        try:
            lines = output.splitlines()
            for line in lines:
                if module_name in line:
                    parts = line.split()
                    start, end = int(parts[0], 16), int(parts[1], 16)
                    pykd.dprintln(f"|-> From 0x{hex(start)} to 0x{hex(end)}")
                    return start, end
        except (IndexError, ValueError):
            pykd.dprintln("[!] Failed to parse module address range.")
    else:
        pykd.dprintln(f"[!] Module '{module_name}' not found.")
    return None, None


def run(cmd: str) -> str:
    """Executes a debugger command and returns its output."""
    try:
        return pykd.dbgCommand(cmd)
    except Exception as e:
        pykd.dprintln(f"[!] Error executing '{cmd}': {e}")
        return ""


def analyze_cave(start_addr: str) -> int:
    """
    Analyzes a memory region to locate a code cave starting from a given address.

    This function searches for a contiguous empty memory region, or code cave,
    starting from `start_addr`. It iterates through memory in 4-byte increments,
    stopping when non-zero data is detected, and rewinds to the last empty region
    to set the end address of the identified code cave. The function calculates and
    logs the code cave size, then returns the end address.

    Args:
        start_addr (str): The starting memory address (hexadecimal string) from which
            to search for a code cave.

    Returns:
        int: The hexadecimal end address of the located code cave.
    """
    counter = 0  # Used to move through the memory region

    while True:
        # Read the memory region, moving through it in 4-byte increments
        output = run(f"dd ({start_addr} + 4 * 0n{counter}) L4")
        counter += 1

        # Check if memory region contains data
        if "00000000 00000000 00000000 00000000" not in output:
            # Rewind to the last empty region to set the end address of the code cave
            output = run(f"dd ({start_addr} + 4 * 0n{counter - 1}) L4")
            # 044c9ff4  00000000 00000000 00000000 7c8b5756
            end_address = int(output.split()[0], 16)
            break

    # Calculate the code cave size using the counter
    code_cave_size = (counter + 1) * 4
    pykd.dprintln(f"|-> {code_cave_size} bytes")
    return end_address


def get_protection(addr: str) -> int:
    """
    Retrieves the memory protection level for a specified address.

    This function executes a debugger command to check the memory protection of
    the given address. If successful, it parses the protection flag from the output
    and converts it to an integer. If the command fails or the output cannot be parsed,
    the function returns 0.

    Args:
        addr (str): The memory address to check, given as a hexadecimal string.

    Returns:
        int: The protection level as a hexadecimal integer, or 0 if the protection
        level cannot be determined.
    """
    output = run(f"!vprot {addr}")
    if "Protect:" not in output:
        pykd.dprintln(f"[!] Failed to determine protection for {addr}")
        return 0

    try:
        protection_hex = output.split("Protect:           ")[1].split()[0]
        return int(protection_hex, 16)
    except (IndexError, ValueError) as e:
        pykd.dprintln(f"[!] Error parsing protection for {addr}: {e}")
        return 0


def analyze_memory_chunk(output: str, current_address: int) -> int:
    """
    Analyzes a memory chunk for empty executable regions, identifying potential code caves.

    This function examines the provided memory `output` for empty 16-byte regions,
    indicating possible code caves. If an empty, executable region is detected, it updates
    `current_address` with the address of the identified code cave and triggers further
    analysis via the `analyze_cave` function.

    Args:
        output (str): The memory content output to analyze, formatted as a string with
            hexadecimal address values.
        current_address (int): Tracks the current address being analyzed and updated if a
            code cave is found.

    Returns:
        int: The updated `current_address` if a code cave was found; otherwise, it
        returns the original `current_address`.
    """
    for line in output.splitlines():
        # Check if the region is empty
        if "00000000 00000000 00000000 00000000" in line:
            addr = line.split()[0]
            protection = get_protection(addr)

            if protection in EXEC_PROTECTION_FLAGS:
                pykd.dprintln(
                    f"\n[+] 0x{addr} - {PROTECTION_FLAGS.get(protection)} ({hex(protection)})"
                )
                current_address = analyze_cave(start_addr=addr)

    return current_address


def scan_memory_range(start: int, end: int, current_address: int = 0):
    """
    Scans a specified memory range to locate code caves, analyzing memory in chunks.

    This function iterates over a memory address range from `start` to `end` in increments,
    searching for executable memory regions that are empty (code caves). The function
    recursively adjusts `current_address` if a code cave is found to prevent repeated
    analysis of the same region.

    Args:
        start (int): The starting address of the memory range to scan.
        end (int): The ending address of the memory range to scan.
        current_address (int, optional): Tracks the address of a discovered code cave
            to skip further analysis of the same region. Defaults to 0.

    Returns:
        int: The `current_address`, updated to the last found code cave or 0 if no
        code caves were found within the range.
    """
    for address in range(start, end, 0xA):
        if current_address:
            return scan_memory_range(current_address, end)

        current_address = analyze_memory_chunk(
            output=run(f"dd {hex(address)} L100"), current_address=current_address
        )

    return current_address


def main():
    parser = argparse.ArgumentParser(
        prog="code_caver",
        add_help=True,
        description="Code Cave Scanner in loaded modules/binary",
    )
    parser.add_argument(
        "module_or_start",
        metavar="module_or_start",
        type=str,
        help="Enter module name or start address",
    )
    parser.add_argument(
        "end",
        metavar="endvalue",
        type=str,
        nargs="?",
        help="End address (if start is specified)",
    )

    args = parser.parse_args()

    print_welcome_message()

    # Determine if input is a module name or address range
    start = end = None
    if args.end is None:
        # If no end address, treat the first argument as a module name
        start, end = get_module_range(args.module_or_start)
    else:
        # Else, parse the start and end addresses from arguments
        try:
            start = int(args.module_or_start, 16)
            end = int(args.end, 16)
        except ValueError:
            pykd.dprintln("[!] Invalid address format.")
            sys.exit(0)

    if start is None or end is None:
        pykd.dprintln("[!] Could not determine memory range to scan.")
        sys.exit(0)

    pykd.dprintln(
        f"[*] Scanning for code caves within address range: {hex(start)} - {hex(end)}\n"
    )

    scan_memory_range(start, end)

    pykd.dprintln("\n[+] Done")


if __name__ == "__main__":
    main()
