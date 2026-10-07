from app.subnets import parse_subnet_rules


def test_subnet_rules_normalize_and_reject():
    accepted, ok = parse_subnet_rules(["192.168.1.1/28", "  "], ["10.20.0.1/28", ""])
    assert ok
    assert accepted == [("192.168.1.0/28", "10.20.0.0/28")]

    masked, mask_ok = parse_subnet_rules(
        ["192.168.1.0 255.255.255.240"],
        ["10.20.0.0 255.255.255.240"],
    )
    assert mask_ok
    assert masked == [("192.168.1.0/28", "10.20.0.0/28")]

    assert parse_subnet_rules(["192.168.1.0/28"], ["10.20.0.0/24"])[1] is False
    assert parse_subnet_rules(["192.168.1.0/28"], [""])[1] is False
    assert parse_subnet_rules(["192.168.1.0/28"], ["192.168.1.0/28"])[1] is False
    assert parse_subnet_rules(["192.168.1.0/24", "192.168.2.0/28"], ["10.1.0.0/24", "10.1.0.0/28"])[1] is False
    assert parse_subnet_rules(["0.0.0.0/8"], ["10.0.0.0/8"])[1] is False

    hosts, host_ok = parse_subnet_rules(["192.168.1.1/32"], ["10.50.0.1"])
    assert host_ok
    assert hosts == [("192.168.1.1", "10.50.0.1")]
    assert parse_subnet_rules(["192.168.1.1"], ["10.20.0.0/28"])[1] is False
    assert parse_subnet_rules(["192.168.1.1"], ["192.168.1.1"])[1] is False
