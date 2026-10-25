"""Tests for the pure sort-key/sort-state helpers behind admintui's
sortable Clients/Certificates table columns (admintui/util/table.py's
sort_text_key/sort_version_key/toggle_sort_state) - the same per-function,
no-Textual-widget testing style tests/test_admintui_client_staleness.py
already uses for _last_seen().

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import unittest

from rich.text import Text

from sslcrtsrv.admintui.util.table import (
    HEADER_CLICK_DEBOUNCE_SECONDS, should_debounce_header_click, sort_text_key, sort_version_key,
    toggle_sort_state,
)


class TestSortTextKey(unittest.TestCase):
    def test_normalizes_case(self):
        self.assertEqual(sort_text_key("Zebra"), sort_text_key("zebra"))

    def test_plain_str_and_text_wrapped_cell_normalize_the_same(self):
        self.assertEqual(sort_text_key("host1.example.com"), sort_text_key(Text("host1.example.com")))

    def test_text_wrapped_cell_ignores_style(self):
        self.assertEqual(sort_text_key(Text("Alpha", style="red")), sort_text_key("alpha"))


class TestSortVersionKey(unittest.TestCase):
    def test_minor_version_with_more_digits_sorts_after(self):
        # The motivating case: "0.9.10" must sort after "0.9.8", unlike a
        # plain string comparison which would put it before.
        self.assertGreater(sort_version_key("0.9.10"), sort_version_key("0.9.8"))

    def test_equal_versions_are_equal(self):
        self.assertEqual(sort_version_key("0.9.8"), sort_version_key("0.9.8"))

    def test_ordinary_ascending_order(self):
        versions = ["0.9.8", "0.9.10", "0.9.9", "1.0.0"]
        self.assertEqual(sorted(versions, key=sort_version_key), ["0.9.8", "0.9.9", "0.9.10", "1.0.0"])

    def test_unparseable_value_does_not_raise_and_sorts_after_real_versions(self):
        key = sort_version_key("N/A")
        self.assertGreater(key, sort_version_key("99.99.99"))


class TestShouldDebounceHeaderClick(unittest.TestCase):
    def test_nothing_handled_yet_never_debounces(self):
        self.assertFalse(should_debounce_header_click(None, None, "Client ID", 100.0))

    def test_same_column_within_the_window_is_debounced(self):
        self.assertTrue(should_debounce_header_click(
            "Client ID", 100.0, "Client ID", 100.0 + HEADER_CLICK_DEBOUNCE_SECONDS / 2))

    def test_same_column_after_the_window_is_not_debounced(self):
        self.assertFalse(should_debounce_header_click(
            "Client ID", 100.0, "Client ID", 100.0 + HEADER_CLICK_DEBOUNCE_SECONDS * 2))

    def test_a_different_column_is_never_debounced_even_immediately_after(self):
        self.assertFalse(should_debounce_header_click("Client ID", 100.0, "Type", 100.0))


class TestToggleSortState(unittest.TestCase):
    def test_clicking_the_same_column_flips_direction(self):
        column, reverse = toggle_sort_state("Client ID", False, "Client ID")
        self.assertEqual(column, "Client ID")
        self.assertTrue(reverse)

        column, reverse = toggle_sort_state("Client ID", True, "Client ID")
        self.assertEqual(column, "Client ID")
        self.assertFalse(reverse)

    def test_clicking_a_different_column_switches_to_it_ascending(self):
        column, reverse = toggle_sort_state("Client ID", True, "Type")
        self.assertEqual(column, "Type")
        self.assertFalse(reverse)

    def test_clicking_from_no_sort_starts_ascending(self):
        column, reverse = toggle_sort_state(None, False, "Version")
        self.assertEqual(column, "Version")
        self.assertFalse(reverse)


if __name__ == "__main__":
    unittest.main()
