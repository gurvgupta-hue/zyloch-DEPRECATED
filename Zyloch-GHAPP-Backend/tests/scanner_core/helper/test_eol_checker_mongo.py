"""Tests that EOL data is read from the MongoDB cache (not live APIs)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scanner_core.helpers.eol_checker import (
    COLLECTION_ENDOFLIFE,
    _mongo_fetch_endoflife,
    check_eol_for_versions_with_origins,
    eol_fetch_product,
    summarize_eol,
)


PYTHON_RELEASES = [
    {
        "name": "3.12",
        "isEol": False,
        "isMaintained": True,
        "latest": {"name": "3.12.7"},
        "releaseDate": "2023-10-02",
    },
]


@pytest.fixture
def mock_mongo_db():
    db = MagicMock()
    collection = MagicMock()
    db.__getitem__.return_value = collection
    return db, collection


class TestMongoFetchEndoflife:
    def test_returns_releases_from_eol_collection(self, mock_mongo_db):
        db, collection = mock_mongo_db
        collection.find_one.return_value = {"releases": PYTHON_RELEASES}

        with patch("scanner_core.helpers.eol_checker._get_mongo_db", return_value=db):
            result = _mongo_fetch_endoflife("python")

        assert result == PYTHON_RELEASES
        db.__getitem__.assert_called_once_with(COLLECTION_ENDOFLIFE)
        collection.find_one.assert_called_once_with(
            {"slug": "python"},
            {"releases": 1, "_id": 0},
        )

    def test_returns_none_when_document_missing(self, mock_mongo_db):
        db, collection = mock_mongo_db
        collection.find_one.return_value = None

        with patch("scanner_core.helpers.eol_checker._get_mongo_db", return_value=db):
            assert _mongo_fetch_endoflife("missing-slug") is None


class TestEolFetchProductUsesMongo:
    def test_prefers_mongo_cache_over_live_api(self):
        with patch(
            "scanner_core.helpers.eol_checker._mongo_fetch_endoflife",
            return_value=PYTHON_RELEASES,
        ) as mongo_mock:
            with patch("requests.get") as live_api_mock:
                result = eol_fetch_product("python")

        mongo_mock.assert_called_once_with("python")
        live_api_mock.assert_not_called()
        assert result == PYTHON_RELEASES


class TestSummarizeEolFromMongo:
    def test_builds_result_from_mongo_backed_releases(self):
        with patch(
            "scanner_core.helpers.eol_checker.eol_fetch_product",
            return_value=PYTHON_RELEASES,
        ):
            result = summarize_eol("python", "python", "3.12.1")

        assert result is not None
        assert result.product == "python"
        assert result.current_version == "3.12.1"
        assert result.parent_version == "3.12"
        assert result.status == "supported"
        assert result.latest == "3.12.7"


class TestCheckEolWithOriginsFromMongo:
    def test_python_eol_in_output_uses_mongo_data(self):
        with patch(
            "scanner_core.helpers.eol_checker.eol_fetch_product",
            return_value=PYTHON_RELEASES,
        ):
            results = check_eol_for_versions_with_origins(
                {"python": "3.12.1"},
                origins={"python": {"3.12.1": ["/repo/.python-version"]}},
            )

        python_result = results.get("python")
        assert python_result is not None
        assert python_result["status"] == "supported"
        assert python_result["current_version"] == "3.12.1"
        assert python_result["source_files"] == ["/repo/.python-version"]
