"""Synthetic delivery quote entry point for the P4 evaluation."""

import sys

from pricing import delivery_fee, parse_quantity


def main(argv):
    quantity = parse_quantity(argv[0] if argv else "")
    if quantity is None:
        return "invalid quantity"
    return str(delivery_fee(quantity, member="--member" in argv[1:]))


if __name__ == "__main__":
    print(main(sys.argv[1:]))
