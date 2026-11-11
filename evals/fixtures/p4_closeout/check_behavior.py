"""Run the same assertions against either copy of the synthetic project."""

import unittest

from app import main
from pricing import delivery_fee


class Behavior(unittest.TestCase):
    def test_cli_quote(self):
        self.assertEqual(main(["5", "--member"]), "4")

    def test_zero_quantity(self):
        self.assertEqual(delivery_fee(0, priority=True), 0)

    def test_standard_quote(self):
        self.assertEqual(delivery_fee(1), 8)

    def test_discount_stack(self):
        self.assertEqual(delivery_fee(5, member=True, coupon=True, prepaid=True), 2)

    def test_transport_stack(self):
        self.assertEqual(delivery_fee(10, priority=True, remote=True, fragile=True), 19)
