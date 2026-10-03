import pytest

from netprobe.ports import MAX_HOSTS, TOP_PORTS, expand_targets, parse_ports


def test_single_port():
    assert parse_ports("80") == [80]


def test_list_and_range_are_sorted_and_unique():
    assert parse_ports("443, 22,80,20-22") == [20, 21, 22, 80, 443]


def test_top_preset():
    assert parse_ports("top") == list(TOP_PORTS)
    assert 22 in TOP_PORTS and 443 in TOP_PORTS


def test_all_preset():
    ports = parse_ports("all")
    assert ports[0] == 1 and ports[-1] == 65535 and len(ports) == 65535


def test_top_can_be_combined_with_extra_ports():
    assert 12345 in parse_ports("top,12345")


@pytest.mark.parametrize("spec", ["", "  ", ",", "0", "65536", "abc", "80-20", "1-99999", "-5"])
def test_invalid_port_specs(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


def test_expand_plain_host_is_passthrough():
    assert expand_targets("example.com") == ["example.com"]


def test_expand_cidr():
    assert expand_targets("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_expand_single_address_cidr():
    assert expand_targets("10.0.0.5/32") == ["10.0.0.5"]


def test_expand_non_strict_cidr():
    assert len(expand_targets("10.0.0.7/29")) == 6


def test_expand_cidr_too_large():
    with pytest.raises(ValueError, match=str(MAX_HOSTS)):
        expand_targets("10.0.0.0/8")


@pytest.mark.parametrize("target", ["", "10.0.0.0/99", "not/acidr", "2001:db8::/120"])
def test_expand_invalid_targets(target):
    with pytest.raises(ValueError):
        expand_targets(target)
