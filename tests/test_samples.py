"""Round-trip and cross-device checks for the fake sample configurations."""

from pathlib import Path

from app.engine.mapper import Mapper
from app.engine.restore import restore_text
from app.engine.vendors.cisco_ios import remove_secrets, sanitize_config

ROOT = Path(__file__).resolve().parents[1] / "samples"
KEYWORDS = ["Northwind", "Cedar", "Maple"]


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_samples_round_trip_and_drop_secrets():
    files = {
        "catalyst-sw01.cfg": _read("catalyst-sw01.cfg"),
        "isr-rtr01.cfg": _read("isr-rtr01.cfg"),
        "isr-rtr02.cfg": _read("isr-rtr02.cfg"),
    }
    for name, text in files.items():
        mapper = Mapper(keywords=KEYWORDS)
        sanitized = sanitize_config(text, mapper)
        restored = restore_text(sanitized, mapper)
        assert restored == remove_secrets(text), name
        assert "FAKESECRET" not in sanitized
        assert "DEADBEEF" not in sanitized
        folded = sanitized.casefold()
        assert "northwind" not in folded
        assert "cedar" not in folded
        assert "maple" not in folded
        for entry in mapper.all_entries():
            assert "FAKESECRET" not in entry.real
            assert "DEADBEEF" not in entry.real


def test_shared_addresses_use_one_stand_in_across_devices():
    mapper = Mapper(keywords=KEYWORDS)
    switch = sanitize_config(_read("catalyst-sw01.cfg"), mapper)
    router = sanitize_config(_read("isr-rtr01.cfg"), mapper)
    peer = sanitize_config(_read("isr-rtr02.cfg"), mapper)

    def fake(real: str) -> str:
        return mapper.by_key[("ipv4", real)]

    users_a = fake("192.168.10.1")
    users_b = fake("192.168.10.2")
    users_vip = fake("192.168.10.254")
    assert users_a.endswith(".1")
    assert users_b.endswith(".2")
    assert users_vip.endswith(".254")
    assert users_a.rsplit(".", 1)[0] == users_b.rsplit(".", 1)[0] == users_vip.rsplit(".", 1)[0]

    wan_a = fake("203.0.113.1")
    wan_b = fake("203.0.113.2")
    assert wan_a.endswith(".1") and wan_b.endswith(".2")
    assert wan_a.rsplit(".", 1)[0] == wan_b.rsplit(".", 1)[0]

    tunnel_a = fake("10.255.0.1")
    tunnel_b = fake("10.255.0.2")
    assert tunnel_a.endswith(".1") and tunnel_b.endswith(".2")
    assert tunnel_a.rsplit(".", 1)[0] == tunnel_b.rsplit(".", 1)[0]

    tacacs = fake("10.10.20.30")
    ntp = fake("192.168.10.20")
    peer_ip = fake("198.51.100.10")
    for stand_in in (tacacs, ntp, users_vip, wan_a):
        assert stand_in in switch or stand_in in router
    assert tacacs in router and tacacs in peer
    assert ntp in router and ntp in peer
    assert wan_a in router and wan_a in peer
    assert peer_ip in router and peer_ip in peer
    assert "255.255.255.252" in router and "255.255.255.252" in peer
    assert "0.0.0.255" in router
    assert "224.0.0.5" in router
    assert "GigabitEthernet1/0/1" in switch
    assert "GigabitEthernet0/0/0" in router
    assert "Port-channel1" in switch
