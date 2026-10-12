"""Tests for scanner_core.helpers.license_risk - SPDX license -> risk level,
including name normalization and AND/OR compound license expressions."""
from __future__ import annotations

import pytest

from scanner_core.helpers.license_risk import get_license_risk_level


class TestExactSpdxKeys:
    @pytest.mark.parametrize(
        "license_val,expected",
        [
            ("MIT", "Low"),
            ("Apache-2.0", "Low"),
            ("BSD-3-Clause", "Low"),
            ("LGPL-2.1", "Medium"),
            ("GPL-3.0", "High"),
            ("AGPL-3.0", "High"),
            ("LicenseRef-Enterprise", "Variable"),
        ],
    )
    def test_known_spdx_ids(self, license_val: str, expected: str):
        assert get_license_risk_level(license_val) == expected

    @pytest.mark.parametrize("license_val", [None, "", "-", "unknown", "UNKNOWN", "NOASSERTION"])
    def test_missing_or_empty_defaults_to_high(self, license_val):
        assert get_license_risk_level(license_val) == "High"

    def test_unmapped_real_license_defaults_to_high(self):
        assert get_license_risk_level("Some-Obscure-License-9.9") == "High"


class TestLicenseNameNormalization:
    """A human-readable license name/phrase must resolve to the same risk as
    its SPDX id - this was the bug: "MIT License" fell through to the "High"
    default instead of matching "MIT" -> "Low"."""

    @pytest.mark.parametrize(
        "license_val",
        [
            "MIT",
            "mit",
            "MIT License",
            "The MIT License",
            "The MIT License (MIT)",
            "MIT License (MIT)",
            "License MIT",
        ],
    )
    def test_mit_variants_all_resolve_low(self, license_val: str):
        assert get_license_risk_level(license_val) == "Low"

    @pytest.mark.parametrize(
        "license_val",
        [
            "Apache-2.0",
            "Apache License 2.0",
            "Apache License, Version 2.0",
            "The Apache Software License, Version 2.0",
            "Apache 2.0",
            "Apache2",
            "Apache License",  # falls to the generic "apache" pattern -> 2.0
        ],
    )
    def test_apache_variants_all_resolve_low(self, license_val: str):
        assert get_license_risk_level(license_val) == "Low"

    @pytest.mark.parametrize(
        "license_val",
        [
            "BSD-3-Clause",
            "BSD 3-Clause License",
            "The BSD 3-Clause License",
            "New BSD License",
            "Revised BSD License",
            "3-Clause BSD License",
        ],
    )
    def test_bsd_3_clause_variants_all_resolve_low(self, license_val: str):
        assert get_license_risk_level(license_val) == "Low"

    def test_bsd_2_clause_variant_resolves_low(self):
        assert get_license_risk_level("BSD 2-Clause License") == "Low"

    @pytest.mark.parametrize(
        "license_val",
        [
            "GPL-3.0",
            "GNU General Public License, Version 3",
            "GPL 3.0",
            "GNU General Public License v3",
        ],
    )
    def test_gpl3_variants_all_resolve_high(self, license_val: str):
        assert get_license_risk_level(license_val) == "High"

    def test_lgpl_generic_text_resolves_medium(self):
        assert get_license_risk_level("GNU Lesser General Public License") == "Medium"

    def test_agpl_text_resolves_high(self):
        assert get_license_risk_level("GNU Affero General Public License v3") == "High"


class TestAndCompoundLicense:
    """Conjunctive "A AND B" - both licenses apply, so the combined obligation
    is the worst case among them."""

    def test_two_low_risk_licenses_stays_low(self):
        assert get_license_risk_level("MIT AND BSD-3-Clause") == "Low"

    def test_low_and_high_picks_high(self):
        assert get_license_risk_level("GPL-3.0 AND MIT") == "High"
        assert get_license_risk_level("MIT AND GPL-3.0") == "High"

    def test_lowercase_and_separator_also_works(self):
        assert get_license_risk_level("MIT and GPL-3.0") == "High"

    def test_and_resolves_human_readable_names_too(self):
        assert get_license_risk_level("MIT License and GNU General Public License v3") == "High"

    def test_and_with_one_unmapped_member_ignores_it(self):
        # Only the recognized member(s) count; an unmapped one is skipped
        # rather than forcing the whole expression to the "High" default.
        assert get_license_risk_level("MIT AND Some-Obscure-License-9.9") == "Low"


class TestOrCompoundLicense:
    """Disjunctive "A OR B" - the licensee picks one, so the real risk is
    whichever member is actually the lowest."""

    def test_low_or_high_picks_low(self):
        assert get_license_risk_level("GPL-3.0 OR MIT") == "Low"
        assert get_license_risk_level("MIT OR GPL-3.0") == "Low"

    def test_two_high_risk_licenses_stays_high(self):
        assert get_license_risk_level("GPL-3.0 OR AGPL-3.0") == "High"

    def test_lowercase_or_separator_also_works(self):
        assert get_license_risk_level("MIT or GPL-3.0") == "Low"

    def test_or_resolves_human_readable_names_too(self):
        assert get_license_risk_level("GNU General Public License v3 or MIT License") == "Low"


class TestAndOrPriority:
    def test_and_wins_when_both_present(self):
        # Matches the frontend's check order (AND checked before OR).
        assert get_license_risk_level("MIT AND GPL-3.0 OR ISC") == "High"


class TestLicenseNameContainingAndOr:
    """A license whose own full name contains "and"/"or" (e.g. CDDL's "Common
    Development AND Distribution License") must resolve directly as that one
    license, never get mis-split into two unrelated AND/OR halves."""

    def test_cddl_full_name_is_not_split_on_its_own_and(self):
        assert get_license_risk_level("Common Development and Distribution License") == "Medium"
        assert get_license_risk_level("common development and distribution license") == "Medium"

    def test_cddl_exact_id_unaffected(self):
        assert get_license_risk_level("CDDL-1.0") == "Medium"
        assert get_license_risk_level("CDDL-1.1") == "Medium"


class TestRemainingLicensePolicyMapCoverage:
    """Every category in LICENSE_POLICY_MAP.json should resolve correctly from
    common real-world phrasings, not just the ecosystems already covered."""

    @pytest.mark.parametrize(
        "license_val,expected",
        [
            ("Clear BSD License", "Low"),
            ("BSD Zero Clause License", "Low"),
            ("0BSD", "Low"),
            ("Python Software Foundation License", "Low"),
            ("Boost Software License", "Low"),
            ("Artistic License", "Low"),
            ("Artistic-1.0", "Low"),
            ("Common Public License", "Medium"),
            ("MPL-1.0", "Medium"),
            ("Creative Commons Attribution 4.0", "Medium"),
            ("CC BY-SA 4.0", "Medium"),
            ("CC BY-NC 4.0", "Medium"),
            ("CC BY-NC-SA 4.0", "Medium"),
            ("CC BY-NC-ND 4.0", "Medium"),
            ("Freeware", "Medium"),
            ("Shareware", "Medium"),
            ("Proprietary", "Medium"),
            ("Commercial License", "Medium"),
            ("Microsoft EULA", "Medium"),
            ("End User License Agreement", "Medium"),
            ("Open Software License 3.0", "High"),
            ("European Union Public License", "High"),
            ("Server Side Public License", "High"),
            ("Business Source License", "High"),
            ("Commons Clause", "High"),
            ("Elastic License 2.0", "High"),
            ("All Rights Reserved", "High"),
            ("Unlicensed", "High"),
            ("No License", "High"),
            ("Enterprise License", "Variable"),
            ("Custom License", "Variable"),
            ("Vendor-Specific License", "Variable"),
        ],
    )
    def test_covers_every_remaining_category(self, license_val: str, expected: str):
        assert get_license_risk_level(license_val) == expected

    def test_boost_and_business_source_stay_disambiguated(self):
        # "BSL" (Boost, Low) vs "BUSL"/"Business Source" (High) must never
        # collide via a bare abbreviation match.
        assert get_license_risk_level("Boost Software License") == "Low"
        assert get_license_risk_level("Business Source License") == "High"
        assert get_license_risk_level("BUSL-1.1") == "High"
        assert get_license_risk_level("BSL-1.0") == "Low"
