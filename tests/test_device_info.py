"""Check device naming without installing Home Assistant: python tests/test_device_info.py."""
import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

# Only the HA types used by device_info are needed for this standalone check.
for name in ("homeassistant", "homeassistant.config_entries", "homeassistant.helpers", "homeassistant.helpers.entity"):
    sys.modules[name] = types.ModuleType(name)
sys.modules["homeassistant.config_entries"].ConfigEntry = SimpleNamespace
sys.modules["homeassistant.helpers.entity"].DeviceInfo = dict
pkg = types.ModuleType("zyx")
pkg.__path__ = [str(Path(__file__).resolve().parents[1] / "custom_components" / "ha_zyxel")]
sys.modules["zyx"] = pkg
build = importlib.import_module("zyx.device_info").build_device_info
entry = SimpleNamespace(entry_id="test-router", data={"host": "https://192.0.2.1"})

for data in (None, {}, {"device": None}, {"device": {"DeviceInfo": {"ModelName": " "}}}):
    info = build(entry, data)
    assert info["name"] == "Zyxel (https://192.0.2.1)"
    assert info["model"] == ""
    assert info["sw_version"] is None

for source in ("device", "cardpage"):
    info = build(entry, {source: {"DeviceInfo": {"ModelName": " NR7302 ", "SoftwareVersion": " 1.0 "}}})
    assert info["name"] == "Zyxel NR7302"
    assert info["model"] == "NR7302"
    assert info["sw_version"] == "1.0"
    assert info["identifiers"] == {("ha_zyxel", entry.entry_id)}
    assert info["configuration_url"] == entry.data["host"]
    assert info["serial_number"] is None

info = build(entry, {"device": {"DeviceInfo": {"ModelName": "NR7302"}},
                     "cardpage": {"DeviceInfo": {"ModelName": "fallback", "SoftwareVersion": "1.0"}}})
assert info["name"] == "Zyxel NR7302"
assert info["sw_version"] == "1.0"
print("Device naming: OK")
