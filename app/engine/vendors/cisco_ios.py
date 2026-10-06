"""Cisco IOS and IOS-XE running-config rules.

Secrets are replaced with ``<REMOVED>`` and are not written into the mapping
table. IPv4 hosts keep their host bits inside a stand-in subnet of the same
prefix length. Interface names such as ``GigabitEthernet1/0/1`` are left as
written. Whitespace and line order are preserved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.engine.iputil import (
    ENC_TYPES,
    IPV4_RE,
    is_contiguous_mask,
    is_contiguous_wildcard,
    is_exempt,
    parse_ipv4,
    prefix_len,
    prefix_to_mask,
)
from app.engine.issues import Issue
from app.engine.mapper import TOKEN_TYPES, Mapper

_TOKEN_RE = re.compile(r'"[^"\r\n]*"|\'[^\'\r\n]*\'|\S+')
_PROTECTED_RE = re.compile(
    r"<REMOVED>"
    r"|(?<![A-Za-z0-9_-])(?:HOST|USER|DESC|BANNER|VLAN|LOC|CONTACT|REMARK|ACL|RMAP|CMAP|OBJ|PFX|CHAIN|KEY|NAME|CHASSIS)-\d+(?![A-Za-z0-9_-])"
    r"|(?<![A-Za-z0-9_-])example-\d+\.local(?![A-Za-z0-9_-])"
)
_PLACEHOLDER_RE = re.compile(
    r"(?<![A-Za-z0-9_-])((?:HOST|USER|DESC|BANNER|VLAN|LOC|CONTACT|REMARK|ACL|RMAP|CMAP|OBJ|PFX|CHAIN|KEY|NAME|CHASSIS)-\d+|example-\d+\.local)(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
_IP_ADDR_RE = re.compile(
    r"(?i)^\s*ip\s+address\s+"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?:/(?P<pfx>\d{1,2})|\s+(?P<mask>(?:\d{1,3}\.){3}\d{1,3}))"
    r"(?:\s+secondary)?\s*$"
)
_HEX_RE = re.compile(r"^(\s*)([0-9A-Fa-f][0-9A-Fa-f \t]*)$")
_BANNER_RE = re.compile(r"(?i)^(\s*banner\s+\S+\s+)(.*)$")

_TOP_PARENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)^vlan\s+\d+\b"), "vlan"),
    (re.compile(r"(?i)^interface\s+\S+"), "interface"),
    (re.compile(r"(?i)^line\s+"), "line"),
    (re.compile(r"(?i)^router\s+bgp\b"), "bgp"),
    (re.compile(r"(?i)^router\s+ospf\b"), "ospf"),
    (re.compile(r"(?i)^router\s+eigrp\b"), "eigrp"),
    (re.compile(r"(?i)^tacacs\s+server\s+\S+"), "aaa_server"),
    (re.compile(r"(?i)^radius\s+server\s+\S+"), "aaa_server"),
    (re.compile(r"(?i)^aaa\s+group\s+server\b"), "aaa_group"),
    (re.compile(r"(?i)^aaa\s+server\s+radius\s+dynamic-author\b"), "dynauth"),
    (re.compile(r"(?i)^key\s+chain\s+\S+"), "keychain"),
    (re.compile(r"(?i)^crypto\s+ikev2\s+keyring\s+\S+"), "ikev2_keyring"),
    (re.compile(r"(?i)^crypto\s+keyring\s+\S+"), "keyring"),
    (re.compile(r"(?i)^crypto\s+pki\s+certificate\s+chain\b"), "cert_chain"),
    (re.compile(r"(?i)^ip\s+dhcp\s+pool\s+\S+"), "dhcp"),
    (re.compile(r"(?i)^object-group\s+"), "object_group"),
    (re.compile(r"(?i)^ip\s+access-list\s+"), "acl"),
    (re.compile(r"(?i)^route-map\s+\S+"), "route_map"),
    (re.compile(r"(?i)^crypto\s+dynamic-map\s+\S+"), "crypto_map"),
    (re.compile(r"(?i)^crypto\s+map\s+\S+"), "crypto_map"),
]

_NAME_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)^ip\s+access-list\s+(?:standard|extended)\s+(\S+)"), "acl"),
    (re.compile(r"(?i)^route-map\s+(\S+)"), "routemap"),
    (re.compile(r"(?i)^crypto\s+dynamic-map\s+(\S+)"), "cryptomap"),
    (re.compile(r"(?i)^crypto\s+map\s+(\S+)"), "cryptomap"),
    (re.compile(r"(?i)^object-group\s+\S+\s+(\S+)"), "object"),
    (re.compile(r"(?i)^ip\s+prefix-list\s+(\S+)"), "prefixlist"),
    (re.compile(r"(?i)^key\s+chain\s+(\S+)"), "keychain"),
    (re.compile(r"(?i)^crypto\s+ikev2\s+keyring\s+(\S+)"), "keychain"),
    (re.compile(r"(?i)^crypto\s+keyring\s+(\S+)"), "keychain"),
    (re.compile(r"(?i)^class-map\s+(?:type\s+\S+\s+)?(?:match-any|match-all\s+)?(\S+)"), "name"),
    (re.compile(r"(?i)^policy-map\s+(?:type\s+\S+\s+)?(\S+)"), "name"),
    (re.compile(r"(?i)^vrf\s+definition\s+(\S+)"), "name"),
    (re.compile(r"(?i)^ip\s+vrf\s+(\S+)"), "name"),
    (re.compile(r"(?i)^crypto\s+pki\s+certificate\s+chain\s+(\S+)"), "name"),
    (re.compile(r"(?i)^crypto\s+pki\s+trustpoint\s+(\S+)"), "name"),
    (re.compile(r"(?i)^ip\s+dhcp\s+pool\s+(\S+)"), "name"),
]

_FULL_FIELDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)^(\s*description\s+)(\S.*)$"), "description"),
    (re.compile(r"(?i)^(\s*remark\s+)(\S.*)$"), "remark"),
    (re.compile(r"(?i)^(snmp-server\s+location\s+)(\S.*)$"), "snmp_location"),
    (re.compile(r"(?i)^(snmp-server\s+contact\s+)(\S.*)$"), "snmp_contact"),
    (re.compile(r"(?i)^(snmp-server\s+chassis-id\s+)(\S.*)$"), "chassis"),
]

_HASH_ALGS = frozenset({"md5", "sha", "sha1", "sha2", "sha224", "sha256", "sha384", "sha512"})
_PRIV_ALGS = frozenset({"des", "3des", "aes", "aes128", "aes192", "aes256"})


@dataclass
class Context:
    parent: str = "global"
    mode: str = "config"  # config, banner, cert
    banner_delim: str | None = None


@dataclass
class LineEvent:
    tag: str
    lead: str = ""
    delim: str = ""
    banner_text: str = ""
    banner_suffix: str = ""


@dataclass
class Discovery:
    subnets: list[tuple[int, int]] = field(default_factory=list)
    seen_subnets: set[tuple[int, int]] = field(default_factory=set)
    hostnames: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    vlans: list[str] = field(default_factory=list)
    names: list[tuple[str, str]] = field(default_factory=list)

    def add_subnet(self, network: int, prefix: int) -> None:
        key = (network, prefix)
        if key not in self.seen_subnets:
            self.seen_subnets.add(key)
            self.subnets.append(key)


def sanitize_config(text: str, mapper: Mapper) -> str:
    discovery = _discover(text, mapper.keywords)
    for network, prefix in discovery.subnets:
        mapper.ensure_subnet(network, prefix)
    for hostname in discovery.hostnames:
        mapper.map_value("hostname", hostname)
    for domain in discovery.domains:
        mapper.map_value("domain", domain)
    for username in discovery.usernames:
        mapper.map_value("username", username)
    for vlan in discovery.vlans:
        mapper.map_value("vlan", vlan)
    for kind, value in discovery.names:
        mapper.map_value(kind, value)
    return _walk(text, mapper)


def remove_secrets(text: str) -> str:
    """Drop secret values only. Used to define the sanitize/restore round trip."""
    return _walk(text, None)


def find_issues(text: str, mapper: Mapper) -> list[Issue]:
    known = mapper.placeholders()
    real_ips = mapper.reals_of("ipv4")
    placeholder_ips = mapper.placeholders_of("ipv4")
    real_hosts = {value.casefold() for value in mapper.reals_of("hostname")}
    real_users = {value.casefold() for value in mapper.reals_of("username")}
    real_domains = {value.casefold() for value in mapper.reals_of("domain")}
    issues: list[Issue] = []
    for number, line in enumerate(text.splitlines(), start=1):
        excerpt = line if len(line) <= 240 else line[:237] + "..."
        if "<REMOVED>" in line:
            issues.append(
                Issue(
                    number,
                    "removed_secret",
                    "Secret was removed. Fill it in manually, or keep the existing device value. Do not paste <REMOVED> onto the device.",
                    excerpt,
                )
            )
        stripped = line.strip()
        roles = _roles_for_line(line)
        matches = list(IPV4_RE.finditer(line))
        for index, match in enumerate(matches):
            if roles[index] != "address":
                continue
            ip = match.group(0)
            try:
                if is_exempt(parse_ipv4(ip)):
                    continue
            except ValueError:
                continue
            if ip in placeholder_ips:
                continue
            if ip in real_ips:
                issues.append(
                    Issue(
                        number,
                        "real_ip_present",
                        f"{ip} matches a real address in this session and is not a stand-in. It was left unchanged.",
                        excerpt,
                    )
                )
            else:
                issues.append(
                    Issue(
                        number,
                        "unmapped_ip",
                        f"{ip} is not in the session mapping. It may be a value added while editing.",
                        excerpt,
                    )
                )
        for match in _PLACEHOLDER_RE.finditer(line):
            token = match.group(1)
            if token not in known:
                issues.append(
                    Issue(
                        number,
                        "unmapped_placeholder",
                        f"{token} looks like a ConfigMask stand-in but this session did not issue it.",
                        excerpt,
                    )
                )
        host = re.match(r"(?i)^hostname\s+(\S+)", stripped)
        if host and host.group(1) not in known:
            value = host.group(1)
            if value.casefold() in real_hosts:
                message = f"hostname {value} matches an original name in this session, not a stand-in."
                code = "real_hostname_present"
            else:
                message = f"hostname {value} is not in the session mapping."
                code = "unmapped_hostname"
            issues.append(Issue(number, code, message, excerpt))
        domain = re.match(r"(?i)^ip\s+domain(?:-name|\s+name)\s+(\S+)", stripped)
        if domain and domain.group(1) not in known:
            value = domain.group(1)
            if value.casefold() in real_domains:
                message = f"domain {value} matches an original domain in this session, not a stand-in."
                code = "real_domain_present"
            else:
                message = f"domain {value} is not in the session mapping."
                code = "unmapped_domain"
            issues.append(Issue(number, code, message, excerpt))
        user = re.match(r"(?i)^username\s+(\S+)", stripped)
        if user:
            value = user.group(1)
            if value not in known and value != "<REMOVED>":
                if value.casefold() in real_users:
                    message = f"username {value} matches an original username in this session, not a stand-in."
                    code = "real_username_present"
                else:
                    message = f"username {value} is not in the session mapping."
                    code = "unmapped_username"
                issues.append(Issue(number, code, message, excerpt))
    return issues


class CiscoIOSVendor:
    id = "cisco_ios"
    label = "Cisco IOS / IOS-XE"

    def sanitize(self, text: str, mapper: Mapper) -> str:
        return sanitize_config(text, mapper)

    def find_issues(self, text: str, mapper: Mapper) -> list[Issue]:
        return find_issues(text, mapper)


def _walk(text: str, mapper: Mapper | None) -> str:
    token_re = _compile_tokens(mapper) if mapper is not None else None
    keyword_re = _compile_keywords(mapper.keywords) if mapper is not None else None
    ctx = Context()
    pieces: list[str] = []
    for body, ending in _iter_lines(text):
        event = _analyze(body, ctx)
        pieces.append(_render(body, event, ctx, mapper, token_re, keyword_re) + ending)
    return "".join(pieces)


def _discover(text: str, keywords: list[str]) -> Discovery:
    found = Discovery()
    ctx = Context()
    for body, _ending in _iter_lines(text):
        event = _analyze(body, ctx)
        if event.tag not in {"normal", "cert_header"}:
            continue
        _learn_subnet(body, found)
        _learn_identifiers(body, ctx, found)
    client_names: list[tuple[str, str]] = []
    for kind, value in found.names:
        if _contains_client_text(value, keywords, found.hostnames, found.domains):
            client_names.append((kind, value))
    found.names = client_names
    return found


def _learn_subnet(body: str, found: Discovery) -> None:
    match = _IP_ADDR_RE.match(body)
    if not match:
        return
    try:
        ip = parse_ipv4(match.group("ip"))
    except ValueError:
        return
    if is_exempt(ip):
        return
    if match.group("pfx"):
        prefix = int(match.group("pfx"))
        if not 8 <= prefix <= 30:
            return
        mask = prefix_to_mask(prefix)
    else:
        try:
            mask = parse_ipv4(match.group("mask"))
        except ValueError:
            return
        if not is_contiguous_mask(mask):
            return
        prefix = prefix_len(mask)
        if not 8 <= prefix <= 30:
            return
    found.add_subnet(ip & mask, prefix)


def _learn_identifiers(body: str, ctx: Context, found: Discovery) -> None:
    stripped = body.strip()
    tokens = list(_TOKEN_RE.finditer(body))
    if not tokens:
        return
    first = _bare(tokens[0])
    if first == "hostname" and len(tokens) >= 2:
        _append_unique(found.hostnames, tokens[1].group(0))
    if first == "username" and len(tokens) >= 2:
        _append_unique(found.usernames, tokens[1].group(0))
    if first == "snmp-server" and len(tokens) >= 3 and _bare(tokens[1]) == "user":
        _append_unique(found.usernames, tokens[2].group(0))
    if first == "ip" and len(tokens) >= 3 and _bare(tokens[1]) == "host":
        _append_unique(found.hostnames, tokens[2].group(0))
    if first == "ppp" and "sent-username" in {_bare(tok) for tok in tokens}:
        lows = [_bare(tok) for tok in tokens]
        index = lows.index("sent-username")
        if index + 1 < len(tokens):
            _append_unique(found.usernames, tokens[index + 1].group(0))
    domain = re.match(r"(?i)^\s*ip\s+domain(?:-name|\s+name|\s+list)\s+(\S+)\s*$", body)
    if domain:
        _append_unique(found.domains, domain.group(1))
    dhcp_domain = re.match(r"(?i)^\s*domain-name\s+(\S+)\s*$", body)
    if dhcp_domain and ctx.parent == "dhcp":
        _append_unique(found.domains, dhcp_domain.group(1))
    if ctx.parent == "vlan":
        vlan = re.match(r"(?i)^\s*name\s+(\S+)\s*$", body)
        if vlan:
            _append_unique(found.vlans, vlan.group(1))
    for pattern, kind in _NAME_RULES:
        match = pattern.match(stripped)
        if match:
            found.names.append((kind, match.group(1)))
            break


def _contains_client_text(value: str, keywords: list[str], hostnames: list[str], domains: list[str]) -> bool:
    folded = value.casefold()
    for keyword in keywords:
        if keyword.casefold() in folded:
            return True
    for item in hostnames:
        if len(item) >= 4 and item.casefold() in folded:
            return True
    for item in domains:
        if len(item) >= 4 and item.casefold() in folded:
            return True
    return False


def _render(
    body: str,
    event: LineEvent,
    ctx: Context,
    mapper: Mapper | None,
    token_re: tuple[re.Pattern[str], dict[str, str]] | None,
    keyword_re: re.Pattern[str] | None,
) -> str:
    tag = event.tag
    if tag == "cert_body":
        return _redact_hex_line(body)
    if tag == "cert_end" or tag == "banner_end":
        return body
    if tag == "banner_body":
        if mapper is None or body.strip() == "":
            return body
        return mapper.map_value("banner", body)
    if tag == "banner_close_text":
        if mapper is None:
            return body
        placeholder = mapper.map_value("banner", event.banner_text) if event.banner_text else ""
        return placeholder + event.banner_suffix
    if tag == "banner_open":
        if mapper is None:
            return body
        placeholder = mapper.map_value("banner", event.banner_text) if event.banner_text else ""
        return f"{event.lead}{event.delim}{placeholder}{event.banner_suffix}"
    if tag == "plain":
        if mapper is None:
            return body
        return _mask_free(body, mapper, token_re, keyword_re)
    line = _redact_secrets(body, ctx)
    if mapper is None:
        return line
    if line == body:
        field = _full_field(body, ctx, mapper)
        if field is not None:
            return field
    return _mask_free(line, mapper, token_re, keyword_re)


def _mask_free(
    line: str,
    mapper: Mapper,
    token_re: tuple[re.Pattern[str], dict[str, str]] | None,
    keyword_re: re.Pattern[str] | None,
) -> str:
    line = _replace_tokens(line, token_re)
    line = _replace_ips(line, mapper)
    return _apply_keywords(line, mapper, keyword_re)


def _full_field(body: str, ctx: Context, mapper: Mapper) -> str | None:
    for pattern, kind in _FULL_FIELDS:
        match = pattern.match(body)
        if match:
            return match.group(1) + mapper.map_value(kind, match.group(2))
    if ctx.parent == "vlan":
        match = re.match(r"(?i)^(\s*name\s+)(\S+)(\s*)$", body)
        if match:
            return match.group(1) + mapper.map_value("vlan", match.group(2)) + match.group(3)
    return None


def _analyze(body: str, ctx: Context) -> LineEvent:
    if ctx.mode == "banner":
        return _analyze_banner(body, ctx)
    if ctx.mode == "cert":
        return _analyze_cert(body, ctx)
    stripped = body.strip()
    is_top = bool(body) and body[0] not in " \t" and bool(stripped) and not stripped.startswith("!")
    if is_top:
        ctx.parent = "global"
        ctx.mode = "config"
        for pattern, name in _TOP_PARENTS:
            if pattern.match(stripped):
                ctx.parent = name
                break
        banner = _BANNER_RE.match(body)
        if banner:
            parsed = _split_banner_rest(banner.group(2))
            if parsed is not None:
                delim, text, suffix, closed = parsed
                if not closed:
                    ctx.mode = "banner"
                    ctx.banner_delim = delim
                return LineEvent(
                    "banner_open",
                    lead=banner.group(1),
                    delim=delim,
                    banner_text=text,
                    banner_suffix=suffix,
                )
        return LineEvent("normal")
    if ctx.parent == "cert_chain" and re.match(r"(?i)^certificate\b", stripped):
        ctx.mode = "cert"
        return LineEvent("cert_header")
    if not stripped or stripped.startswith("!"):
        return LineEvent("plain")
    return LineEvent("normal")


def _analyze_banner(body: str, ctx: Context) -> LineEvent:
    delim = ctx.banner_delim or ""
    if delim and delim in body:
        index = body.find(delim)
        before = body[:index]
        suffix = body[index:]
        ctx.mode = "config"
        ctx.banner_delim = None
        if before.strip() == "":
            return LineEvent("banner_end")
        return LineEvent("banner_close_text", banner_text=before, banner_suffix=suffix)
    return LineEvent("banner_body")


def _analyze_cert(body: str, ctx: Context) -> LineEvent:
    stripped = body.strip()
    if stripped.lower() == "quit":
        ctx.mode = "config"
        return LineEvent("cert_end")
    if body and body[0] not in " \t" and stripped and not stripped.startswith("!"):
        ctx.mode = "config"
        return _analyze(body, ctx)
    return LineEvent("cert_body")


def _split_banner_rest(rest: str) -> tuple[str, str, str, bool] | None:
    if rest.startswith("^C"):
        delim, payload = "^C", rest[2:]
    elif rest.startswith("\x03"):
        delim, payload = "\x03", rest[1:]
    elif rest:
        delim, payload = rest[0], rest[1:]
    else:
        return None
    index = payload.find(delim)
    if index >= 0:
        return delim, payload[:index], payload[index:], True
    return delim, payload, "", False


def _redact_hex_line(body: str) -> str:
    match = _HEX_RE.match(body)
    if not match:
        return body
    compact = re.sub(r"\s+", "", match.group(2))
    if len(compact) < 8 or not re.fullmatch(r"[0-9A-Fa-f]+", compact):
        return body
    return match.group(1) + "<REMOVED>"


def _redact_secrets(body: str, ctx: Context) -> str:
    for handler in (
        _handle_enable,
        _handle_username,
        _handle_snmp_community,
        _handle_snmp_user,
        _handle_snmp_host,
        _handle_legacy_aaa,
        _handle_server_private,
        _handle_context_key,
        _handle_config_key,
        _handle_isakmp,
        _handle_psk,
        _handle_tunnel_key,
        _handle_ospf_key,
        _handle_key_string,
        _handle_neighbor_password,
        _handle_ntp,
        _handle_ppp,
        _handle_wpa,
        _handle_fhrp,
        _handle_ip_password,
        _handle_server_key,
        _handle_password,
    ):
        updated = handler(body, ctx)
        if updated is not None:
            return updated
    return body


def _handle_enable(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if not tokens or _bare(tokens[0]) != "enable":
        return None
    lows = [_bare(tok) for tok in tokens]
    if "secret" not in lows and "password" not in lows:
        return None
    index = max(pos for pos, word in enumerate(lows) if word in {"secret", "password"})
    cursor = index + 1
    if cursor < len(tokens) and lows[cursor] == "level":
        cursor += 2
    if cursor < len(tokens) and _bare(tokens[cursor]) in ENC_TYPES and cursor + 1 < len(tokens):
        cursor += 1
    if cursor >= len(tokens):
        return body
    return _splice(body, [(tokens[cursor].start(), tokens[cursor].end(), "<REMOVED>")])


def _handle_username(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if not tokens or _bare(tokens[0]) != "username":
        return None
    lows = [_bare(tok) for tok in tokens]
    hits = [pos for pos, word in enumerate(lows) if word in {"secret", "password"}]
    if not hits:
        return None
    return _splice(body, _value_after(tokens, hits[-1]))


def _handle_snmp_community(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 3 or _bare(tokens[0]) != "snmp-server" or _bare(tokens[1]) != "community":
        return None
    return _splice(body, [(tokens[2].start(), tokens[2].end(), "<REMOVED>")])


def _handle_snmp_user(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 4 or _bare(tokens[0]) != "snmp-server" or _bare(tokens[1]) != "user":
        return None
    lows = [_bare(tok) for tok in tokens]
    spans: list[tuple[int, int, str]] = []
    if "auth" in lows:
        index = lows.index("auth")
        cursor = index + 1
        if cursor < len(tokens) and lows[cursor] in _HASH_ALGS:
            cursor += 1
        if cursor < len(tokens) and lows[cursor] not in {"priv", "access", "v1", "v2c", "v3"}:
            spans.append((tokens[cursor].start(), tokens[cursor].end(), "<REMOVED>"))
    if "priv" in lows:
        index = lows.index("priv")
        cursor = index + 1
        if cursor < len(tokens) and lows[cursor] in _PRIV_ALGS:
            cursor += 1
        if cursor < len(tokens) and lows[cursor] in {"128", "192", "256"}:
            cursor += 1
        if cursor < len(tokens):
            spans.append((tokens[cursor].start(), tokens[cursor].end(), "<REMOVED>"))
    return _splice(body, spans) if spans else body


def _handle_snmp_host(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 4 or _bare(tokens[0]) != "snmp-server" or _bare(tokens[1]) != "host":
        return None
    lows = [_bare(tok) for tok in tokens]
    if "version" not in lows:
        return body
    index = lows.index("version")
    if index + 2 >= len(tokens):
        return body
    if lows[index + 1] in {"1", "2", "2c"}:
        secret = tokens[index + 2]
        return _splice(body, [(secret.start(), secret.end(), "<REMOVED>")])
    return body


def _handle_legacy_aaa(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 3:
        return None
    head = _bare(tokens[0])
    if head not in {"tacacs-server", "radius-server"}:
        return None
    lows = [_bare(tok) for tok in tokens]
    if "key" not in lows:
        return body
    return _splice(body, _value_after(tokens, lows.index("key")))


def _handle_server_private(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if not tokens or _bare(tokens[0]) != "server-private":
        return None
    lows = [_bare(tok) for tok in tokens]
    if "key" not in lows:
        return body
    return _splice(body, _value_after(tokens, lows.index("key")))


def _handle_context_key(body: str, ctx: Context) -> str | None:
    if ctx.parent != "aaa_server":
        return None
    tokens = _tokens(body)
    if not tokens or _bare(tokens[0]) != "key":
        return None
    if len(tokens) >= 2 and _bare(tokens[1]) in {"chain", "config-key"}:
        return None
    return _splice(body, _value_after(tokens, 0))


def _handle_config_key(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 3 or _bare(tokens[0]) != "key" or _bare(tokens[1]) != "config-key":
        return None
    last = tokens[-1]
    return _splice(body, [(last.start(), last.end(), "<REMOVED>")])


def _handle_isakmp(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 4:
        return None
    if not (_bare(tokens[0]) == "crypto" and _bare(tokens[1]) == "isakmp" and _bare(tokens[2]) == "key"):
        return None
    cursor = 3
    if (
        cursor < len(tokens)
        and _bare(tokens[cursor]) in ENC_TYPES
        and cursor + 1 < len(tokens)
        and _bare(tokens[cursor + 1]) not in {"address", "hostname"}
    ):
        cursor += 1
    if cursor >= len(tokens) or _bare(tokens[cursor]) in {"address", "hostname"}:
        return body
    secret = tokens[cursor]
    return _splice(body, [(secret.start(), secret.end(), "<REMOVED>")])


def _handle_psk(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if not tokens or _bare(tokens[0]) != "pre-shared-key":
        return None
    lows = [_bare(tok) for tok in tokens]
    if "key" in lows[1:]:
        index = len(lows) - 1 - lows[::-1].index("key")
        return _splice(body, _value_after(tokens, index))
    if len(tokens) >= 2 and lows[1] in {"local", "remote"}:
        return _splice(body, _value_after(tokens, 1))
    return _splice(body, _value_after(tokens, 0))


def _handle_tunnel_key(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 3 or _bare(tokens[0]) != "tunnel" or _bare(tokens[1]) != "key":
        return None
    secret = tokens[2]
    return _splice(body, [(secret.start(), secret.end(), "<REMOVED>")])


def _handle_ospf_key(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 3 or _bare(tokens[0]) != "ip" or _bare(tokens[1]) != "ospf":
        return None
    kind = _bare(tokens[2])
    if kind == "authentication-key":
        return _splice(body, _value_after(tokens, 2))
    if kind == "message-digest-key":
        lows = [_bare(tok) for tok in tokens]
        if "md5" not in lows:
            return body
        return _splice(body, _value_after(tokens, lows.index("md5")))
    return None


def _handle_key_string(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if not tokens or _bare(tokens[0]) != "key-string":
        return None
    return _splice(body, _value_after(tokens, 0))


def _handle_neighbor_password(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if not tokens or _bare(tokens[0]) != "neighbor":
        return None
    lows = [_bare(tok) for tok in tokens]
    if "password" not in lows:
        return None
    return _splice(body, _value_after(tokens, lows.index("password")))


def _handle_ntp(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 4 or _bare(tokens[0]) != "ntp" or _bare(tokens[1]) != "authentication-key":
        return None
    lows = [_bare(tok) for tok in tokens]
    for index, word in enumerate(lows):
        if word in _HASH_ALGS or word.startswith("cmac"):
            return _splice(body, _value_after(tokens, index))
    return body


def _handle_ppp(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if not tokens or _bare(tokens[0]) != "ppp":
        return None
    lows = [_bare(tok) for tok in tokens]
    if "password" not in lows:
        return None
    return _splice(body, _value_after(tokens, lows.index("password")))


def _handle_wpa(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 2 or _bare(tokens[0]) != "wpa-psk":
        return None
    if len(tokens) >= 2 and _bare(tokens[1]) in {"ascii", "hex"}:
        return _splice(body, _value_after(tokens, 1))
    return _splice(body, _value_after(tokens, 0))


def _handle_fhrp(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if not tokens or _bare(tokens[0]) not in {"standby", "vrrp", "glbp"}:
        return None
    lows = [_bare(tok) for tok in tokens]
    if "authentication" not in lows:
        return None
    if "key-string" in lows:
        return _splice(body, _value_after(tokens, lows.index("key-string")))
    if "text" in lows:
        return _splice(body, _value_after(tokens, lows.index("text")))
    return _splice(body, _value_after(tokens, lows.index("authentication")))


def _handle_ip_password(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if len(tokens) < 3 or _bare(tokens[0]) != "ip":
        return None
    lows = [_bare(tok) for tok in tokens]
    if "password" not in lows:
        return None
    if lows[1] == "ftp" or (lows[1] == "http" and "client" in lows):
        return _splice(body, _value_after(tokens, lows.index("password")))
    return None


def _handle_server_key(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if not tokens:
        return None
    lows = [_bare(tok) for tok in tokens]
    if "server-key" not in lows:
        return None
    return _splice(body, _value_after(tokens, lows.index("server-key")))


def _handle_password(body: str, _ctx: Context) -> str | None:
    tokens = _tokens(body)
    if not tokens or _bare(tokens[0]) != "password":
        return None
    if len(tokens) > 1 and _bare(tokens[1]) == "encryption":
        return None
    return _splice(body, _value_after(tokens, 0))


def _value_after(tokens: list[re.Match[str]], keyword_index: int) -> list[tuple[int, int, str]]:
    cursor = keyword_index + 1
    if cursor >= len(tokens):
        return []
    if _bare(tokens[cursor]) in ENC_TYPES and cursor + 1 < len(tokens):
        nxt = _bare(tokens[cursor + 1])
        if nxt not in {"address", "hostname"}:
            cursor += 1
    if cursor >= len(tokens):
        return []
    token = tokens[cursor]
    return [(token.start(), token.end(), "<REMOVED>")]


def _roles_for_line(line: str) -> list[str]:
    matches = list(IPV4_RE.finditer(line))
    roles = ["address"] * len(matches)
    index = 0
    while index < len(matches):
        try:
            ip = parse_ipv4(matches[index].group(0))
        except ValueError:
            roles[index] = "exempt"
            index += 1
            continue
        if index + 1 < len(matches):
            try:
                nxt = parse_ipv4(matches[index + 1].group(0))
            except ValueError:
                nxt = None
            between = line[matches[index].end() : matches[index + 1].start()]
            if nxt is not None:
                kind = _pair_kind(between, nxt)
                if kind in {"mask", "wildcard"}:
                    roles[index] = "exempt" if is_exempt(ip) else "address"
                    roles[index + 1] = kind
                    index += 2
                    continue
        roles[index] = "exempt" if is_exempt(ip) else "address"
        index += 1
    return roles


def _pair_kind(between: str, second: int) -> str | None:
    match = re.fullmatch(r"\s*(mask|netmask|wildcard)?\s*", between, flags=re.IGNORECASE)
    if not match:
        return None
    keyword = (match.group(1) or "").lower()
    if keyword == "wildcard":
        return "wildcard"
    if keyword in {"mask", "netmask"}:
        return "mask"
    if second == 0:
        return "mask"
    if is_contiguous_mask(second) and not is_contiguous_wildcard(second):
        return "mask"
    if (second >> 24) == 0 and not is_contiguous_mask(second):
        return "wildcard"
    if is_contiguous_mask(second):
        return "mask"
    return None


def _replace_ips(line: str, mapper: Mapper) -> str:
    matches = list(IPV4_RE.finditer(line))
    if not matches:
        return line
    roles = _roles_for_line(line)
    spans: list[tuple[int, int, str]] = []
    for index, match in enumerate(matches):
        if roles[index] != "address":
            continue
        original = match.group(0)
        try:
            if is_exempt(parse_ipv4(original)):
                continue
        except ValueError:
            continue
        fake = mapper.map_ip(original)
        if fake != original:
            spans.append((match.start(), match.end(), fake))
    return _splice(line, spans)


def _compile_tokens(mapper: Mapper) -> tuple[re.Pattern[str], dict[str, str]] | None:
    pairs: list[tuple[str, str]] = []
    for (kind, real), placeholder in mapper.by_key.items():
        if kind in TOKEN_TYPES and real:
            pairs.append((real, placeholder))
    if not pairs:
        return None
    pairs.sort(key=lambda item: len(item[0]), reverse=True)
    lookup = {real: placeholder for real, placeholder in pairs}
    parts = [
        r"(?<![A-Za-z0-9_-])" + re.escape(real) + r"(?![A-Za-z0-9_-])" for real, _placeholder in pairs
    ]
    return re.compile("|".join(parts)), lookup


def _compile_keywords(keywords: list[str]) -> re.Pattern[str] | None:
    """Match a keyword and the identifier it sits inside.

    ``CEDAR-WIFI`` and ``TS-CEDAR`` become one stand-in, not ``KEY-001-WIFI``.
    A multi-word keyword such as ``Cedar Lab`` still matches as a phrase.
    """
    if not keywords:
        return None
    ordered = sorted(set(keywords), key=len, reverse=True)
    parts = [
        r"[A-Za-z0-9_.-]*" + re.escape(keyword) + r"[A-Za-z0-9_.-]*" for keyword in ordered
    ]
    return re.compile("|".join(parts), re.IGNORECASE)


def _replace_tokens(line: str, compiled: tuple[re.Pattern[str], dict[str, str]] | None) -> str:
    if compiled is None:
        return line
    pattern, lookup = compiled

    def repl(match: re.Match[str]) -> str:
        return lookup[match.group(0)]

    return _sub_outside(line, pattern, repl)


def _apply_keywords(line: str, mapper: Mapper, pattern: re.Pattern[str] | None) -> str:
    if pattern is None:
        return line

    def repl(match: re.Match[str]) -> str:
        return mapper.map_keyword(match.group(0))

    return _sub_outside(line, pattern, repl)


def _sub_outside(line: str, pattern: re.Pattern[str], repl) -> str:
    pieces: list[str] = []
    last = 0
    for match in _PROTECTED_RE.finditer(line):
        pieces.append(pattern.sub(repl, line[last : match.start()]))
        pieces.append(match.group(0))
        last = match.end()
    pieces.append(pattern.sub(repl, line[last:]))
    return "".join(pieces)


def _tokens(body: str) -> list[re.Match[str]]:
    return list(_TOKEN_RE.finditer(body))


def _bare(token: re.Match[str]) -> str:
    return token.group(0).strip("\"'").lower()


def _splice(body: str, spans: list[tuple[int, int, str]]) -> str:
    for start, end, new in sorted(spans, key=lambda item: item[0], reverse=True):
        body = body[:start] + new + body[end:]
    return body


def _append_unique(bucket: list[str], value: str) -> None:
    if value and value not in bucket:
        bucket.append(value)


def _iter_lines(text: str):
    if text == "":
        return
    for part in text.splitlines(keepends=True):
        if part.endswith("\r\n"):
            yield part[:-2], "\r\n"
        elif part.endswith("\n"):
            yield part[:-1], "\n"
        elif part.endswith("\r"):
            yield part[:-1], "\r"
        else:
            yield part, ""
