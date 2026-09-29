"""Contract schemas and tests, namespaced separately from service test modules."""
# ponytail: package marker so pytest names contracts/test_*.py as contracts.test_*,
# avoiding a top-level basename clash with services/*/test_*.py (e.g. test_coverage.py)
# in the same pytest run. services/ dirs are hyphenated, so they can't be packaged instead.
