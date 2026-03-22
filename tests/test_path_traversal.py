"""Tests for path traversal bypass prevention in _matches_path."""

from __future__ import annotations

import pytest

from intent_guard.sdk.engine import IntentGuardEngine


class TestPathTraversalBypass:
    """Ensure _matches_path is not bypassable with path traversal tricks."""

    @pytest.mark.parametrize(
        "path, pattern",
        [
            ("src/./auth/config.py", "src/auth/*"),
            ("src/auth/../auth/config.py", "src/auth/*"),
            ("src//auth//config.py", "src/auth/*"),
            ("./././.env", ".env"),
            ("src/./auth/../auth/./config.py", "src/auth/*"),
        ],
    )
    def test_traversal_paths_match_protected_pattern(self, path: str, pattern: str):
        assert IntentGuardEngine._matches_path(path, pattern)

    @pytest.mark.parametrize(
        "path, pattern",
        [
            ("src/auth/config.py", "src/auth/*"),
            ("src/auth/login.py", "src/auth/*.py"),
            (".env", ".env"),
            ("config/settings.yaml", "config/*"),
        ],
    )
    def test_normal_paths_still_match(self, path: str, pattern: str):
        assert IntentGuardEngine._matches_path(path, pattern)

    @pytest.mark.parametrize(
        "path, pattern",
        [
            ("src/utils/helper.py", "src/auth/*"),
            ("README.md", "src/auth/*"),
            ("other/.env", ".env"),
        ],
    )
    def test_unrelated_paths_do_not_match(self, path: str, pattern: str):
        assert not IntentGuardEngine._matches_path(path, pattern)
