

import re
from typing import Dict, List, NamedTuple, Optional, Pattern, Tuple


class _License(NamedTuple):
    key: str                       
    risk: str                      
    aliases: Tuple[str, ...] = () 
    patterns: Tuple[str, ...] = () 

_LICENSES: Tuple[_License, ...] = (
    # --- Open-Source-Permissive ---
    _License("MIT", "Low",
             aliases=("mit license", "the mit license", "the mit license (mit)",
                       "mit license (mit)", "license mit"),
             patterns=(r"\bmit\b",)),
    _License("Apache-2.0", "Low",
             aliases=("the apache software license, version 2.0", "the apache license, version 2.0",
                       "apache license, version 2.0", "apache license 2.0", "apache license v2.0",
                       "apache 2.0", "apache2"),
             patterns=(r"\bapache\b",)),
    _License("Apache-1.1", "Low",
             aliases=("the apache software license, version 1.1",),
             patterns=(r"\bapache\b.{0,15}\b1\.1\b|\b1\.1\b.{0,15}\bapache\b",)),
    _License("BSD-3-Clause", "Low",
             aliases=("bsd license", "new bsd license", "revised bsd license",
                       "the bsd 3-clause license", "bsd 3-clause license",
                       "bsd 3 clause", "bsd 3-clause"),
             patterns=(r"\bbsd\b.{0,20}\b3[- ]?clause\b|\b3[- ]?clause\b.{0,20}\bbsd\b|\b(new|modified|revised)\s+bsd\b",
                       r"\bbsd\b")),  # bare fallback last - must lose to the more specific BSD patterns below
    _License("BSD-2-Clause", "Low",
             aliases=("the bsd 2-clause license", "bsd 2-clause license",
                       "bsd 2 clause", "bsd 2-clause"),
             patterns=(r"\bbsd\b.{0,20}\b2[- ]?clause\b|\b2[- ]?clause\b.{0,20}\bbsd\b",)),
    _License("BSD-3-Clause-Clear", "Low",
             aliases=("clear bsd license", "the clear bsd license", "bsd 3-clause clear license")),
    _License("ISC", "Low", aliases=("isc license",), patterns=(r"\bisc\b",)),
    _License("0BSD", "Low",
             aliases=("bsd zero clause license", "zero clause bsd", "zero-clause bsd")),
    _License("Unlicense", "Low", aliases=("the unlicense",), patterns=(r"\bunlicense\b",)),
    _License("CC0-1.0", "Low",
             aliases=("creative commons cc0", "cc0 1.0 universal"),
             patterns=(r"\bcc0\b|\bpublic domain\b",)),
    _License("Zlib", "Low", aliases=("zlib license",), patterns=(r"\bzlib\b",)),
    _License("Python-2.0", "Low",
             aliases=("python software foundation license", "psf license", "psfl"),
             patterns=(r"\bpython software foundation\b|\bpsf license\b|\bpsfl\b",)),
    _License("Artistic-1.0", "Low", aliases=("artistic license 1.0",)),
    _License("Artistic-2.0", "Low",
             aliases=("artistic license", "artistic license 2.0"),
             patterns=(r"\bartistic license\b",)),
    _License("BSL-1.0", "Low",
             aliases=("boost software license", "boost software license 1.0"),
             patterns=(r"\bboost software license\b",)),
    _License("WTFPL", "Medium", patterns=(r"\bwtfpl\b",)),
    _License("CC-BY-3.0", "Medium", aliases=("creative commons attribution 3.0",)),
    _License("CC-BY-4.0", "Medium",
             aliases=("creative commons attribution", "creative commons attribution 4.0",
                       "cc by", "cc-by"),
             patterns=(r"\bcc[- ]?by\b|\bcreative commons attribution\b",)),

    # --- Open-Source-WeakCopyleft ---
    _License("LGPL-2.0", "Medium"),
    _License("LGPL-2.0-only", "Medium"),
    _License("LGPL-2.0-or-later", "Medium"),
    _License("LGPL-2.1", "Medium",
             aliases=("gnu lesser general public license, version 2.1", "lgpl 2.1"),
             patterns=(r"\blgpl\b|\blesser general public license\b",)),
    _License("LGPL-2.1-only", "Medium"),
    _License("LGPL-2.1-or-later", "Medium"),
    _License("LGPL-3.0", "Medium",
             aliases=("gnu lesser general public license, version 3", "lgpl 3.0"),
             patterns=(r"\b(lgpl|lesser general public license)\b.{0,15}\b3(\.0)?\b",)),
    _License("LGPL-3.0-only", "Medium"),
    _License("LGPL-3.0-or-later", "Medium"),
    _License("MPL-1.0", "Medium"),
    _License("MPL-1.1", "Medium"),
    _License("MPL-2.0", "Medium",
             aliases=("mozilla public license 2.0", "mozilla public license, version 2.0"),
             patterns=(r"\bmpl\b|\bmozilla public license\b",)),
    _License("MPL-2.0-no-copyleft-exception", "Medium"),
    _License("EPL-1.0", "Medium",
             aliases=("eclipse public license 1.0", "eclipse public license - v 1.0"),
             patterns=(r"\b(eclipse public license|epl)\b.{0,15}\b1(\.0)?\b",)),
    _License("EPL-2.0", "Medium",
             aliases=("eclipse public license 2.0", "eclipse public license - v 2.0"),
             patterns=(r"\beclipse public license\b|\bepl\b",)),
    _License("CDDL-1.0", "Medium",
             aliases=("common development and distribution license",
                       "common development and distribution license 1.0"),
             patterns=(r"\bcommon development and distribution license\b|\bcddl\b",)),
    _License("CDDL-1.1", "Medium",
             aliases=("common development and distribution license 1.1",)),
    _License("CPL-1.0", "Medium",
             aliases=("common public license", "common public license 1.0"),
             patterns=(r"\bcommon public license\b",)),
    _License("CC-BY-SA-3.0", "Medium"),
    _License("CC-BY-SA-4.0", "Medium",
             aliases=("creative commons attribution-sharealike", "creative commons attribution share alike",
                       "cc by-sa", "cc-by-sa")),

    # --- Open-Source-StrongCopyleft ---
    _License("GPL-1.0", "High"),
    _License("GPL-1.0-only", "High"),
    _License("GPL-1.0-or-later", "High"),
    _License("GPL-2.0", "High",
             aliases=("gnu general public license, version 2", "gpl 2.0"),
             patterns=(r"\bgpl\b|\bgeneral public license\b",)),
    _License("GPL-2.0-only", "High"),
    _License("GPL-2.0-or-later", "High"),
    _License("GPL-3.0", "High",
             aliases=("gnu general public license, version 3", "gpl 3.0"),
             patterns=(r"\b(gpl|general public license)\b.{0,15}\b3(\.0)?\b",)),
    _License("GPL-3.0-only", "High"),
    _License("GPL-3.0-or-later", "High"),
    _License("AGPL-1.0", "High"),
    _License("AGPL-1.0-only", "High"),
    _License("AGPL-1.0-or-later", "High"),
    _License("AGPL-3.0", "High",
             aliases=("gnu affero general public license, version 3",),
             patterns=(r"\baffero\b|\bagpl\b",)),
    _License("AGPL-3.0-only", "High"),
    _License("AGPL-3.0-or-later", "High"),
    _License("OSL-3.0", "High",
             aliases=("open software license", "open software license 3.0"),
             patterns=(r"\bopen software license\b|\bosl\b",)),
    _License("EUPL-1.1", "High", aliases=("european union public license 1.1",)),
    _License("EUPL-1.2", "High",
             aliases=("european union public license", "european union public license 1.2"),
             patterns=(r"\beuropean union public license\b|\beupl\b",)),

    # --- Source-Available-Restricted / Delayed-OpenSource ---
    _License("SSPL-1.0", "High",
             aliases=("server side public license", "server side public license 1.0"),
             patterns=(r"\bserver side public license\b|\bsspl\b",)),
    _License("BUSL-1.1", "High",
             aliases=("business source license", "business source license 1.1"),
             patterns=(r"\bbusiness source license\b|\bbusl\b",)),
    _License("Commons-Clause", "High",
             aliases=("commons clause", "the commons clause", "commons clause license condition"),
             patterns=(r"\bcommons clause\b",)),
    _License("Elastic-2.0", "High",
             aliases=("elastic license", "elastic license 2.0", "elastic license v2"),
             patterns=(r"\belastic license\b",)),

    # --- Proprietary-Commercial ---
    _License("LicenseRef-Proprietary", "Medium",
             aliases=("proprietary", "proprietary license"),
             patterns=(r"\bproprietary\b",)),
    _License("LicenseRef-Commercial", "Medium",
             aliases=("commercial", "commercial license"),
             patterns=(r"\beula\b|\bend[- ]user license agreement\b|\bcommercial license\b|\bcommercial\b",)),
    _License("LicenseRef-Microsoft-EULA", "Medium"),
    _License("LicenseRef-Adobe-EULA", "Medium"),
    _License("LicenseRef-Oracle-EULA", "Medium"),

    # --- Freeware-Shareware ---
    _License("CC-BY-NC-1.0", "Medium"),
    _License("CC-BY-NC-2.0", "Medium"),
    _License("CC-BY-NC-3.0", "Medium"),
    _License("CC-BY-NC-4.0", "Medium",
             aliases=("creative commons attribution-noncommercial",
                       "creative commons attribution non commercial", "cc by-nc", "cc-by-nc")),
    _License("CC-BY-NC-ND-1.0", "Medium"),
    _License("CC-BY-NC-ND-2.0", "Medium"),
    _License("CC-BY-NC-ND-3.0", "Medium"),
    _License("CC-BY-NC-ND-4.0", "Medium",
             aliases=("creative commons attribution-noncommercial-noderivatives",
                       "creative commons attribution-noncommercial-noderivs",
                       "cc by-nc-nd", "cc-by-nc-nd")),
    _License("CC-BY-NC-SA-1.0", "Medium"),
    _License("CC-BY-NC-SA-2.0", "Medium"),
    _License("CC-BY-NC-SA-3.0", "Medium"),
    _License("CC-BY-NC-SA-4.0", "Medium",
             aliases=("creative commons attribution-noncommercial-sharealike",
                       "cc by-nc-sa", "cc-by-nc-sa")),
    _License("LicenseRef-Freeware", "Medium", aliases=("freeware",), patterns=(r"\bfreeware\b",)),
    _License("LicenseRef-Shareware", "Medium", aliases=("shareware",), patterns=(r"\bshareware\b",)),

    # --- Enterprise-Custom ---
    _License("LicenseRef-Enterprise", "Variable",
             aliases=("enterprise license",), patterns=(r"\benterprise license\b",)),
    _License("LicenseRef-Custom", "Variable",
             aliases=("custom license",), patterns=(r"\bcustom license\b",)),
    _License("LicenseRef-Vendor-Specific", "Variable",
             aliases=("vendor-specific license", "vendor specific license"),
             patterns=(r"\bvendor[- ]specific\b",)),

    # --- Unknown / Unlicensed ---
    _License("NOASSERTION", "High"),
    _License("NONE", "High",
             aliases=("all rights reserved", "unlicensed", "no license"),
             patterns=(r"\ball rights reserved\b|\bunlicensed\b|\bno license\b",)),
)

_LICENSE_RISK_LEVELS: Dict[str, str] = {lic.key: lic.risk for lic in _LICENSES}

_LICENSE_NAME_ALIASES: Dict[str, str] = {
    alias: lic.key for lic in _LICENSES for alias in lic.aliases
}

_LICENSES_BY_KEY: Dict[str, _License] = {lic.key: lic for lic in _LICENSES}

_PATTERN_ORDER: Tuple[str, ...] = (
    "BSD-3-Clause", "BSD-2-Clause", "Apache-1.1", "Apache-2.0", "AGPL-3.0",
    "LGPL-3.0", "LGPL-2.1", "GPL-3.0", "GPL-2.0", "MPL-2.0", "EPL-1.0", "EPL-2.0",
    "MIT", "ISC", "Zlib", "Unlicense", "CC0-1.0", "WTFPL", "BSL-1.0", "BUSL-1.1",
    "Python-2.0", "Artistic-2.0", "CDDL-1.0", "CPL-1.0", "OSL-3.0", "EUPL-1.2",
    "SSPL-1.0", "Commons-Clause", "Elastic-2.0", "CC-BY-4.0", "NONE",
    "LicenseRef-Freeware", "LicenseRef-Shareware", "LicenseRef-Vendor-Specific",
    "LicenseRef-Custom", "LicenseRef-Enterprise", "LicenseRef-Commercial",
    "LicenseRef-Proprietary",
)

_LICENSE_TEXT_PATTERNS: List[Tuple[Pattern, str]] = [
    (re.compile(pattern, re.IGNORECASE), key)
    for key in _PATTERN_ORDER
    for pattern in _LICENSES_BY_KEY[key].patterns
]

_keys_with_patterns = {lic.key for lic in _LICENSES if lic.patterns}
_missing_from_order = _keys_with_patterns - set(_PATTERN_ORDER)
assert not _missing_from_order, (
    f"License(s) with .patterns missing from _PATTERN_ORDER: {_missing_from_order}"
)

_RISK_ORDER = {"High": 3, "Medium": 2, "Variable": 2, "Low": 1}

_DEFAULT_RISK_LEVEL = "High"
_AND_SPLIT_RE = re.compile(r"\s+and\s+", re.IGNORECASE)
_OR_SPLIT_RE = re.compile(r"\s+or\s+", re.IGNORECASE)


def _exact_resolve(license_val: str) -> Optional[str]:
    if license_val in _LICENSE_RISK_LEVELS:
        return license_val
    return _LICENSE_NAME_ALIASES.get(license_val.strip().lower())


def _resolve_license_key(license_val: str) -> str:
    exact = _exact_resolve(license_val)
    if exact:
        return exact

    for pattern, key in _LICENSE_TEXT_PATTERNS:
        if pattern.search(license_val):
            return key

    return license_val


def _resolve_compound_risk(parts: List[str], pick) -> Optional[str]:
    levels = [
        _LICENSE_RISK_LEVELS[key]
        for key in (_resolve_license_key(p) for p in parts)
        if key in _LICENSE_RISK_LEVELS
    ]
    if not levels:
        return None
    return pick(levels, key=lambda lvl: _RISK_ORDER.get(lvl, 0))


def get_license_risk_level(license_val: Optional[str]) -> str:
    if not license_val or not isinstance(license_val, str):
        return _DEFAULT_RISK_LEVEL

    value = license_val.strip()
    if not value or value.upper() in ("-", "UNKNOWN", "NOASSERTION"):
        return _DEFAULT_RISK_LEVEL

    exact = _exact_resolve(value)
    if exact:
        return _LICENSE_RISK_LEVELS[exact]

    if _AND_SPLIT_RE.search(value):
        parts = [p.strip() for p in _AND_SPLIT_RE.split(value) if p.strip()]
        return _resolve_compound_risk(parts, max) or _DEFAULT_RISK_LEVEL

    if _OR_SPLIT_RE.search(value):
        parts = [p.strip() for p in _OR_SPLIT_RE.split(value) if p.strip()]
        return _resolve_compound_risk(parts, min) or _DEFAULT_RISK_LEVEL

    return _LICENSE_RISK_LEVELS.get(_resolve_license_key(value), _DEFAULT_RISK_LEVEL)
