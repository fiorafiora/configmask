"""Engine coverage for secrets, address structure, and restore."""

from app.engine.iputil import format_ipv4, parse_ipv4
from app.engine.mapper import Mapper
from app.engine.restore import restore_text
from app.engine.vendors.cisco_ios import find_issues, remove_secrets, sanitize_config

SECRET_CONFIG = """\
hostname NORTHWIND-RTR
!
enable secret 9 $9$FAKESECRET_ENABLE9
enable secret 5 $1$FAKESECRET_ENABLE5
enable password 7 FAKESECRET_ENABLE7
enable algorithm-type scrypt secret FAKESECRET_ENABLE_SCRYPT
enable secret level 15 0 FAKESECRET_ENABLE_LEVEL
!
username netops privilege 15 secret 9 $9$FAKESECRET_USER_SECRET
username "bob smith" password 0 "FAKESECRET_QUOTED"
username helpdesk privilege 1 password 7 FAKESECRET_USER7
username temptest password 0 10.9.8.7
!
ip ftp password 0 FAKESECRET_FTP
ip http client password FAKESECRET_HTTP
!
line con 0
 password 7 FAKESECRET_CON
 login local
line vty 0 4
 password 0 FAKESECRET_VTY
 transport input ssh
!
snmp-server community FAKESECRET_SNMP_COMM RO 10
snmp-server user snmpops SNMPGROUP v3 auth sha FAKESECRET_SNMPAUTH priv aes 128 FAKESECRET_SNMPPRIV
snmp-server host 10.10.20.50 version 2c FAKESECRET_SNMPHOST
snmp-server location Cedar Lab closet
snmp-server contact noc@cedar.northwind.lab
!
tacacs-server key 7 FAKESECRET_TACACS_KEY
tacacs-server host 10.10.20.30 key 0 FAKESECRET_TACACS_HOST
radius-server key FAKESECRET_RADIUS_KEY
radius-server host 10.10.20.31 auth-port 1812 acct-port 1813 key 7 FAKESECRET_RADIUS_HOST
tacacs server TACACS-1
 address ipv4 10.10.20.30
 key 7 FAKESECRET_TACACS_BLOCK
radius server RADIUS-1
 address ipv4 10.10.20.31 auth-port 1812 acct-port 1813
 key FAKESECRET_RADIUS_BLOCK
aaa group server tacacs+ TACACS-CEDAR
 server-private 10.10.20.30 key 0 FAKESECRET_SERVER_PRIVATE
aaa server radius dynamic-author
 client 10.10.20.31 server-key FAKESECRET_SERVER_KEY
!
crypto isakmp key FAKESECRET_ISAKMP address 203.0.113.2
crypto isakmp key 6 FAKESECRET_ISAKMP6 address 198.51.100.1
crypto keyring KR-CEDAR
 pre-shared-key address 203.0.113.2 key FAKESECRET_PSK_ADDR
crypto ikev2 keyring IKEV2-CEDAR
 peer MAPLE
  address 198.51.100.1
  pre-shared-key local FAKESECRET_PSK_LOCAL
  pre-shared-key remote FAKESECRET_PSK_REMOTE
!
interface Tunnel0
 tunnel key FAKESECRET_TUNNEL
!
interface GigabitEthernet0/0/1
 ip ospf authentication-key FAKESECRET_OSPF_AUTH
 ip ospf message-digest-key 1 md5 7 FAKESECRET_OSPF_MD5
 standby 10 authentication md5 key-string 7 FAKESECRET_HSRP
 standby 20 authentication text FAKESECRET_HSRP_TEXT
 vrrp 1 authentication text FAKESECRET_VRRP
!
key chain OSPF-CEDAR
 key 1
  key-string 7 FAKESECRET_KEYCHAIN
!
router bgp 65001
 neighbor 10.255.0.2 password 7 FAKESECRET_BGP
!
ntp authentication-key 1 md5 FAKESECRET_NTP 7
ntp authentication-key 2 md5 7 FAKESECRET_NTP7
!
interface Dialer1
 ppp chap password 0 FAKESECRET_PPP_CHAP
 ppp pap sent-username netops password 0 FAKESECRET_PPP_PAP
!
dot11 ssid CEDAR-WIFI
 wpa-psk ascii 0 FAKESECRET_WPA
 wpa-psk hex FAKESECRET_WPAHEX
!
key config-key password-encrypt FAKESECRET_MASTER
!
crypto pki certificate chain TP-CEDAR
 certificate self-signed 01
  DEADBEEFDEADBEEF DEADBEEFDEADBEEF DEADBEEFDEADBEEF
  AA55AA55AA55AA55 AA55AA55AA55AA55
        quit
!
"""

STRUCTURE = """\
hostname ISR-CEDAR-01
ip domain name cedar.northwind.lab
!
username netops privilege 15
!
vlan 10
 name CEDAR-USERS
!
interface GigabitEthernet0/0/0
 description WAN to Northwind Maple
 ip address 203.0.113.1 255.255.255.252
!
interface GigabitEthernet0/0/1
 description Cedar users
 ip address 192.168.10.1 255.255.255.0
 ip address 192.168.11.1 255.255.255.0 secondary
 ip helper-address 192.168.10.10
 standby 10 ip 192.168.10.254
!
interface Loopback0
 ip address 10.1.5.1 255.255.0.0
!
interface Port-channel1
 description Uplink
!
router ospf 1
 network 192.168.10.0 0.0.0.255 area 0
 network 10.1.0.0 0.0.255.255 area 0
!
router bgp 65001
 neighbor 198.51.100.2 remote-as 65002
 network 192.168.10.0 mask 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 203.0.113.2
ip route 172.16.50.0 255.255.255.0 192.168.10.254
!
access-list 10 permit 192.168.10.0 0.0.0.255
access-list 101 permit ip 192.168.10.0 0.0.0.255 host 198.51.100.10
access-list 101 permit ip any host 224.0.0.5
access-list 101 permit ip any host 224.0.0.6
access-list 101 permit ip any host 224.0.0.10
access-list 101 permit ip host 127.0.0.1 any
access-list 101 permit ip any host 255.255.255.255
!
ip access-list extended CEDAR-MGMT-IN
 remark Allow Cedar operators
 permit tcp 192.168.10.0 0.0.0.255 host 192.168.10.1 eq 22
!
object-group network CEDAR-SERVERS
 host 192.168.10.10
 192.168.11.0 255.255.255.0
!
ip prefix-list CEDAR-OUT seq 5 permit 192.168.10.0/24
ip prefix-list DEFAULT seq 5 permit 0.0.0.0/0
!
route-map CEDAR-OUT permit 10
 set ip next-hop 203.0.113.2
!
crypto map CMAP-CEDAR 10 ipsec-isakmp
 set peer 198.51.100.1
!
ip nat inside source static 192.168.10.10 203.0.113.10
ip name-server 192.0.2.53 198.51.100.53
logging host 192.168.10.40
ntp server 192.168.10.20
snmp-server host 192.168.10.50 version 3 priv netops
ip dhcp excluded-address 192.168.10.1 192.168.10.10
!
banner motd ^C
Northwind Analytics — Cedar Lab
Authorized engineers only.
^C
!
"""

SECOND = """\
hostname ISR-MAPLE-01
!
interface GigabitEthernet0/0/1
 ip address 192.168.10.2 255.255.255.0
!
interface Tunnel0
 ip address 10.255.0.2 255.255.255.252
 tunnel destination 203.0.113.1
!
router bgp 65002
 neighbor 192.168.10.1 remote-as 65001
 neighbor 10.255.0.1 remote-as 65001
!
"""


def test_every_secret_type_is_removed_and_not_stored():
    mapper = Mapper(keywords=["Northwind", "Cedar", "Maple"])
    sanitized = sanitize_config(SECRET_CONFIG, mapper)
    assert "FAKESECRET" not in sanitized
    assert "DEADBEEFDEADBEEF" not in sanitized
    assert "10.9.8.7" not in sanitized
    assert "<REMOVED>" in sanitized
    for entry in mapper.all_entries():
        assert "FAKESECRET" not in entry.real
        assert "FAKESECRET" not in entry.placeholder
        assert "DEADBEEF" not in entry.real
        assert "10.9.8.7" not in entry.real
    # Structural leftovers of the secret commands stay so the engineer can see the hole.
    assert "enable secret 9 <REMOVED>" in sanitized
    assert "enable password 7 <REMOVED>" in sanitized
    assert "snmp-server community <REMOVED> RO 10" in sanitized
    assert "key 1" in sanitized
    assert "key-string 7 <REMOVED>" in sanitized or "key-string <REMOVED>" in sanitized


def test_round_trip_matches_original_except_secrets():
    mapper = Mapper(keywords=["Northwind", "Cedar", "Maple"])
    original = STRUCTURE
    sanitized = sanitize_config(original, mapper)
    restored = restore_text(sanitized, mapper)
    assert restored == remove_secrets(original)
    assert restored == original
    assert "Northwind" not in sanitized.casefold()
    assert "cedar" not in sanitized.casefold()
    assert "maple" not in sanitized.casefold()
    assert "GigabitEthernet0/0/0" in sanitized
    assert "GigabitEthernet0/0/1" in sanitized
    assert "Port-channel1" in sanitized
    assert "interface Vlan10" not in STRUCTURE or "Vlan10" in sanitized or "vlan 10" in sanitized


def test_secret_config_round_trip_keeps_only_removals():
    mapper = Mapper()
    sanitized = sanitize_config(SECRET_CONFIG, mapper)
    restored = restore_text(sanitized, mapper)
    assert restored == remove_secrets(SECRET_CONFIG)
    assert "FAKESECRET" not in restored
    assert "DEADBEEFDEADBEEF" not in restored


def test_ip_mapping_is_consistent_across_configs_and_preserves_hosts():
    mapper = Mapper()
    first = sanitize_config(STRUCTURE, mapper)
    reloaded = Mapper()
    for entry in mapper.all_entries():
        reloaded.load_entry(entry.type, entry.real, entry.placeholder, entry.seq)
    second = sanitize_config(SECOND, reloaded)

    def fake_of(real: str) -> str:
        return mapper.by_key[("ipv4", real)]

    users_gw = fake_of("192.168.10.1")
    users_hsrp = fake_of("192.168.10.254")
    assert users_gw.rsplit(".", 1)[-1] == "1"
    assert users_hsrp.rsplit(".", 1)[-1] == "254"
    assert users_gw.rsplit(".", 1)[0] == users_hsrp.rsplit(".", 1)[0]
    assert fake_of("192.168.10.1") != fake_of("192.168.11.1")

    # /16 interface keeps the host octets.
    loop = fake_of("10.1.5.1")
    assert loop.endswith(".5.1")

    # /30 WAN keeps the host bits in the last octet.
    wan = fake_of("203.0.113.1")
    peer = fake_of("203.0.113.2")
    assert wan.split(".")[-1] == "1"
    assert peer.split(".")[-1] == "2"
    assert ".".join(wan.split(".")[:3]) == ".".join(peer.split(".")[:3])

    # Second device reuses the same stand-ins.
    assert f"ip address {users_gw} " in first or f"ip address {users_gw} " in first
    assert users_gw in second
    assert fake_of("203.0.113.1") in second
    neighbor = reloaded.by_key[("ipv4", "192.168.10.1")]
    assert neighbor == users_gw

    # Public and private stand-ins use the documented pools.
    assert parse_ipv4(users_gw) >> 24 == 10
    wan_net = parse_ipv4(wan)
    assert wan_net >> 16 == (198 << 8) + 18 or (100 << 24) <= (wan_net << 0) >> 0 >> 22
    assert (wan_net & 0xFFFE0000) == 0xC6120000 or (wan_net & 0xFFC00000) == 0x64400000


def test_masks_wildcards_and_exempt_addresses_stay():
    mapper = Mapper()
    sanitized = sanitize_config(STRUCTURE, mapper)
    for literal in (
        "255.255.255.252",
        "255.255.255.0",
        "255.255.0.0",
        "0.0.0.255",
        "0.0.255.255",
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.5",
        "224.0.0.6",
        "224.0.0.10",
        "127.0.0.1",
        "0.0.0.0/0",
        "/24",
    ):
        assert literal in sanitized
    assert "192.168.10." not in sanitized
    assert "203.0.113." not in sanitized
    assert "198.51.100." not in sanitized


def test_keywords_are_case_insensitive_and_stable():
    mapper = Mapper(keywords=["Northwind", "Cedar Lab"])
    text = "!\n! Site Northwind router\n! Cedar Lab closet\n"
    sanitized = sanitize_config(text, mapper)
    assert "northwind" not in sanitized.casefold()
    assert "cedar" not in sanitized.casefold()
    assert sanitized.count("KEY-") == 2
    restored = restore_text(sanitized, mapper)
    assert restored == text

    mixed = Mapper(keywords=["Northwind"])
    messy = "! northwind NORTHWIND\n"
    output = sanitize_config(messy, mixed)
    assert output.count("KEY-001") == 2
    assert "northwind" not in output.casefold()


def test_unmapped_values_are_flagged_with_line_numbers():
    mapper = Mapper(keywords=["Northwind"])
    sanitized = sanitize_config(STRUCTURE, mapper)
    edited = sanitized + "\nip route 203.0.113.50 255.255.255.255 10.250.9.9\nhostname HOST-999\n"
    issues = find_issues(edited, mapper)
    codes = {issue.code for issue in issues}
    assert "unmapped_ip" in codes
    assert "unmapped_hostname" in codes or "unmapped_placeholder" in codes
    route_issues = [issue for issue in issues if "203.0.113.50" in issue.message or "10.250.9.9" in issue.message]
    assert route_issues
    assert route_issues[0].line == edited.splitlines().index(
        "ip route 203.0.113.50 255.255.255.255 10.250.9.9"
    ) + 1
    # Masks and well-known addresses in the original are not flagged.
    flagged_ips = {issue.message.split()[0] for issue in issues if issue.code == "unmapped_ip"}
    assert "255.255.255.255" not in flagged_ips
    assert "224.0.0.5" not in flagged_ips
    assert "0.0.0.0" not in flagged_ips


def test_removed_lines_are_flagged_on_restore():
    mapper = Mapper()
    sanitized = sanitize_config(SECRET_CONFIG, mapper)
    issues = find_issues(sanitized, mapper)
    assert any(issue.code == "removed_secret" for issue in issues)
    assert all("<REMOVED>" in issue.excerpt for issue in issues if issue.code == "removed_secret")


def test_subnet_entries_record_same_prefix_length():
    mapper = Mapper()
    sanitize_config(STRUCTURE, mapper)
    subnets = [entry for entry in mapper.all_entries() if entry.type == "subnet"]
    assert subnets
    for entry in subnets:
        real_prefix = entry.real.split("/")[1]
        fake_prefix = entry.placeholder.split("/")[1]
        assert real_prefix == fake_prefix
        real_net = parse_ipv4(entry.real.split("/")[0])
        # Host bits of the recorded network address are zero.
        prefix = int(real_prefix)
        host_mask = (1 << (32 - prefix)) - 1
        assert real_net & host_mask == 0
        fake_net = parse_ipv4(entry.placeholder.split("/")[0])
        assert fake_net & host_mask == 0
        assert format_ipv4(fake_net) == entry.placeholder.split("/")[0]
        assert entry.placeholder != entry.real


RADIUS_EMBEDDED = """\
radius server dnac-radius_172.21.64.10
 address ipv4 10.0.1.10 auth-port 1812 acct-port 1813
 timeout 4
 retransmit 3
 pac key 7 0725717F7E290A1600421908
radius server other-172.21.64.10
 address ipv4 172.21.64.10 auth-port 1812 acct-port 1813
"""


def test_embedded_ipv4_and_radius_pac_key():
    mapper = Mapper()
    sanitized = sanitize_config(RADIUS_EMBEDDED, mapper)
    assert "172.21.64.10" not in sanitized
    assert "10.0.1.10" not in sanitized
    assert "0725717F7E290A1600421908" not in sanitized
    assert "radius server dnac-radius_10.0.0.10" in sanitized
    assert "address ipv4 10.0.2.10 auth-port 1812 acct-port 1813" in sanitized
    assert "radius server other-10.0.0.10" in sanitized
    assert "pac key 7 <REMOVED>" in sanitized
    for entry in mapper.all_entries():
        assert "0725717F7E290A1600421908" not in entry.real
        assert "0725717F7E290A1600421908" not in entry.placeholder
    assert mapper.by_key[("ipv4", "172.21.64.10")] == "10.0.0.10"
    assert mapper.by_key[("ipv4", "10.0.1.10")] == "10.0.2.10"
    assert mapper.by_key[("subnet", "10.0.1.0/24")] != "10.0.1.0/24"
    restored = restore_text(sanitized, mapper)
    assert restored == remove_secrets(RADIUS_EMBEDDED)
    assert "dnac-radius_172.21.64.10" in restored
    assert "other-172.21.64.10" in restored
    assert "address ipv4 10.0.1.10 " in restored
    assert "address ipv4 172.21.64.10 " in restored
    assert "pac key 7 <REMOVED>" in restored

    whole = Mapper()
    untouched = "ip route 172.21.64.100 255.255.255.255 192.0.2.1\n"
    masked = sanitize_config(untouched, whole)
    assert "172.21.64.10" not in masked
    assert whole.by_key[("ipv4", "172.21.64.100")].endswith(".100")
    assert restore_text(masked, whole) == untouched

    glued = Mapper()
    stuck = "ip route 192.0.2.1 255.255.255.255 host172.21.64.10\n"
    kept = sanitize_config(stuck, glued)
    assert "host172.21.64.10" in kept
    assert ("ipv4", "172.21.64.10") not in glued.by_key


def test_ipv4_restore_uses_digit_boundaries():
    mapper = Mapper()
    mapper.load_entry("ipv4", "172.21.64.1", "10.0.0.1", 1)
    mapper.load_entry("ipv4", "172.21.64.10", "10.0.0.10", 2)
    mapper.load_entry("hostname", "EDGE", "HOST-001", 3)
    mapper.load_entry("description", "closet", "DESC-001", 4)
    text = "dnac-radius_10.0.0.10 other-10.0.0.1 HOST-001 XHOST-001 DESC-001Y\n"
    assert restore_text(text, mapper) == (
        "dnac-radius_172.21.64.10 other-172.21.64.1 EDGE XHOST-001 DESC-001Y\n"
    )
