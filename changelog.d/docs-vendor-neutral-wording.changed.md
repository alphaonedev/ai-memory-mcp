**docs: vendor-neutral provider wording + docs vendor-name gate.** Documentation,
doc comments, config samples and release notes now describe provider support in
vendor-neutral terms, and a new CI step
(`scripts/ci/check_no_cn_ai_vendor.py`, with its unit test and the allowlist
data file `scripts/ci/cn_ai_vendor_allow.json`) keeps the tracked tree at zero
hits for the barred names. Product behaviour is unchanged; only text and
comments moved, plus one test fixture id.
