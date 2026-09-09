"""ClickHouse persistence is optional: with no CLICKHOUSE_PASSWORD the service
runs and emits findings without any ClickHouse dependency; with it set,
persistence is enabled."""
import importlib
import os


def test_ch_disabled_when_no_password():
    os.environ.pop("CLICKHOUSE_PASSWORD", None)
    import app
    importlib.reload(app)
    assert app.CH_ENABLED is False


def test_ch_enabled_when_password_set():
    os.environ["CLICKHOUSE_PASSWORD"] = "x"
    import app
    importlib.reload(app)
    assert app.CH_ENABLED is True
    os.environ.pop("CLICKHOUSE_PASSWORD", None)


if __name__ == "__main__":
    test_ch_disabled_when_no_password()
    test_ch_enabled_when_password_set()
    print("ok test_ch_optional")
