import json

from scripts import vendor_assets


def test_vendored_assets_match_the_lock() -> None:
    assert vendor_assets.check() == []


def test_lock_pins_exact_versions() -> None:
    lock = json.loads(vendor_assets.LOCK.read_text())
    for name, entry in lock.items():
        assert entry["version"].count(".") == 2, name  # exact x.y.z, not a range
        assert entry["integrity"].startswith("sha384-")


def test_tampered_file_is_detected(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for name in vendor_assets.ASSETS.values():
        (tmp_path / name[3]).write_bytes(b"x")
    (tmp_path / "vendor.lock").write_text(vendor_assets.LOCK.read_text())
    monkeypatch.setattr(vendor_assets, "VENDOR_DIR", tmp_path)
    monkeypatch.setattr(vendor_assets, "LOCK", tmp_path / "vendor.lock")
    assert any("does not match" in p for p in vendor_assets.check())
