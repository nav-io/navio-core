"""Central toggle for PSBT usage in functional tests."""

# When set to True, any functional test that relies on PSBT functionality should
# skip their PSBT-specific coverage. Tests should consult this flag before
# executing PSBT-related logic to keep a single point of configuration.
DISABLE_PSBT_TESTS = True
