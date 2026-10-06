# ConfigMask

ConfigMask de-identifies Cisco IOS and IOS-XE router and switch configurations, then puts the real values back after you have an edited copy. It is meant to run in Docker on an internal VM that has no path to the internet. A network engineer uploads a client config, downloads a sanitized copy to discuss with an assistant, then uploads that edited copy to restore the original addresses and names.

Real client data stays in the SQLite database on that VM. Secrets are not stored at all. This repository contains only fake lab configurations (RFC 1918 and documentation addresses). Do not commit a real customer config.

## Workflow

1. Open a session and describe the customer or change. ConfigMask assigns the next job code, for example `JOB-0007`. One session is one mapping table. Upload every device in the job so the same real address becomes the same stand-in on each of them. OSPF neighbors, BGP peers, and IPsec peers stay aligned. The description is encrypted in the database.
2. Optionally add keywords (customer name, site names). Matching is case-insensitive.
3. Upload or paste each running config. Download or copy only the sanitized file.
4. When the edited file comes back, open Restore, paste it, and review the warnings and the diff against the original stored in the session.
5. Download the restored config. Lines that contain `<REMOVED>` still need a human: type the secret on the device, or leave the existing device value. Do not paste `<REMOVED>` onto a router.

The mapping remains in the database, so restore can happen days later without uploading the original again.

## Stand-in addresses

Interface lines `ip address A M` and `ip address A/P` teach the subnet, for prefix lengths /8 through /30. Each real subnet is rewritten to a stand-in subnet with the same prefix length. Host bits are kept, so `.1` and `.254` stay recognizable.

| Real space | Stand-in pool |
| --- | --- |
| RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) | `10.0.0.0/8` |
| Everything else that is rewritten | `198.18.0.0/15` (benchmarking range), then `100.64.0.0/10` if that pool is full |

These are not changed: subnet masks, wildcard masks, prefix lengths, `0.0.0.0`, `255.255.255.255`, `127.0.0.0/8`, and `224.0.0.0/24` (including OSPF `224.0.0.5` / `224.0.0.6` and EIGRP `224.0.0.10`). An address that is not inside a learned interface subnet is mapped as its own `/24`, and that `/24` is remembered for the rest of the session.

Names become tokens such as `HOST-001`, `USER-001`, `DESC-001`, and `example-001.local`. The same real string always receives the same token inside one session. Interface names such as `GigabitEthernet1/0/1`, `Vlan10`, and `Port-channel1` stay as written.

Secrets are replaced with `<REMOVED>` and are never written to the mapping table. That covers enable, username, line, SNMP community and v3 keys, TACACS/RADIUS, ISAKMP and IKEv2 pre-shared keys, tunnel keys, OSPF/EIGRP/BGP authentication, key-chain strings, NTP keys, PPP CHAP/PAP, `wpa-psk`, and the hex body of a `crypto pki certificate chain`. Type 0, 5, 7, 8, and 9 values are included, as are quoted values.

## Run with Docker

The image is self-contained. It does not fetch fonts, scripts, or telemetry at runtime.

```sh
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
cp .env.example .env
# Edit .env. Set the Fernet key, a long CONFIGMASK_SECRET_KEY, and the admin password.
docker compose up --build -d
```

Open `http://127.0.0.1:8741` (or whatever `CONFIGMASK_PORT` is in `.env`). The process inside the container always listens on 8741. Compose publishes `CONFIGMASK_PORT` on the host to that container port.

## Install on an internal Ubuntu server

Run this on a PC that can reach the server and has the SSH private key. The default target is `sysadmin@172.16.40.200`, install path `/opt/tools/configmask`, host port `5599`.

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\deploy.ps1
```

The key is taken from `C:\Users\User\.ssh` (`id_ed25519`, then `id_rsa`). Pass `-KeyPath` if the private key has another name. The script uploads this tree, installs Docker if it is missing, and starts the container. A new server gets a generated admin password, printed once. Back up `/opt/tools/configmask/.env` with the Docker volume.

| Variable | Purpose |
| --- | --- |
| `CONFIGMASK_ADMIN_PASSWORD` | Single admin password. At least 8 characters. Stored only as a scrypt hash in process memory. |
| `CONFIGMASK_SECRET_KEY` | Signs the session cookie. At least 16 characters. |
| `CONFIGMASK_FERNET_KEY` | Encrypts mapping values and stored configs. A Fernet key. Back this up with the volume. |
| `CONFIGMASK_DB_PATH` | SQLite file. In Compose this is `/data/configmask.db`. |
| `CONFIGMASK_PORT` | Host port in Compose. Inside the container the app listens on 8741. |
| `CONFIGMASK_COOKIE_SECURE` | Set to `1` when an HTTPS proxy is in front. The cookie is then marked Secure. |
| `CONFIGMASK_MAX_UPLOAD_BYTES` | Upload limit. Default 10 MiB. |

## Run without Docker

Python 3.12 and the packages in `requirements.txt`.

```sh
python3 -m pip install -r requirements.txt
export CONFIGMASK_ADMIN_PASSWORD='a-local-password'
export CONFIGMASK_SECRET_KEY='a-local-secret-key-value'
export CONFIGMASK_FERNET_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
export CONFIGMASK_DB_PATH=./data/configmask.db
export CONFIGMASK_PORT=8741
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8741
```

The app refuses to start if the password, cookie secret, or Fernet key is missing.

## HTTPS

Put the container behind a reverse proxy on the internal VM. Do not expose it to the internet. Set `CONFIGMASK_COOKIE_SECURE=1`. Example for Caddy on the same host:

```
configmask.internal.example {
    reverse_proxy 127.0.0.1:8741
}
```

There is one admin account. Failed logins pause after eight attempts. Cookies are `SameSite=strict`. API docs are disabled so the UI does not load a CDN.

## Back up the volume

Stop the container so the SQLite snapshot is consistent, then copy the volume. Keep the Fernet key somewhere else. Without that key the copy cannot be decrypted.

```sh
docker compose stop
docker volume ls
docker run --rm -v configmask-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/configmask-data.tgz -C /data .
docker compose start
```

The volume name may be prefixed with the Compose project name. `docker volume ls` shows the actual name. Restore by extracting that archive into an empty volume while the container is stopped.

Logs record session id, job code, byte size, line count, and how many new mappings were written. They do not record configuration text.

## Wipe a session

On the session list, Delete asks for confirmation, then removes that session's mapping rows, stored originals, sanitized copies, and restore history. Other sessions are left alone. Deleting the Docker volume wipes every session.

There is no per-file delete. If one device was uploaded by mistake, delete the session and upload the job again.

## Tests and samples

```sh
python3 -m pytest
```

`samples/catalyst-sw01.cfg` is a fake Catalyst IOS-XE switch. `samples/isr-rtr01.cfg` and `samples/isr-rtr02.cfg` are fake ISR peers with VLANs, SVIs, HSRP, OSPF, EIGRP, BGP, ACLs, object-groups, NAT, an IPsec crypto map, AAA/TACACS, SNMP, NTP, a banner, and a PKI certificate chain. Every secret in those files is a `FAKESECRET_...` marker. Every address is RFC 1918 or a documentation range (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## Adding a vendor

Mapper, restore, and the database are vendor-neutral. Cisco IOS lives in `app/engine/vendors/cisco_ios.py`.

1. Add `app/engine/vendors/<vendor>.py` with `id`, `label`, `sanitize(text, mapper) -> str`, and `find_issues(text, mapper) -> list[Issue]`.
2. Register an instance from `app/engine/vendors/__init__.py`.
3. New sessions store that vendor id. Restore still swaps stand-ins for real values from the shared mapping table.

FortiOS is not implemented yet. The registry test shows the extension point.

## Limitations

- IPv6 is left unchanged. IOS-XR and NX-OS are not supported. Mode tracking assumes `show running-config` indentation: a command at column 0 starts a new block, and `!` does not.
- Subnets are learned only from `ip address` lines, and only for prefixes /8 through /30. `/31` and `/32` fall back to a per-`/24` mapping. A single RFC 1918 `/8` can fill the entire `10.0.0.0/8` stand-in pool.
- Keyword matching is case-insensitive and restores the first spelling that was seen. `northwind` and `NORTHWIND` both come back as whichever form appeared first.
- Text inside descriptions, banners, remarks, SNMP location/contact, and comments is stored (encrypted) so it can be restored. Do not put a password in those fields. Secret commands and certificate hex are not stored.
- An ACL, route-map, object-group, prefix-list, key-chain, VRF, or DHCP-pool name is replaced as a whole token when it contains a keyword, hostname, or domain. A keyword anywhere else consumes the whole identifier around it, so `TS-CEDAR` or `CEDAR-WIFI` becomes one `KEY-00n` token and restores to the original spelling.
- Banner delimiters understood here are a single character, the two-character `^C`, or a raw ETX. `quit` ends a certificate block.
- EIGRP keys are removed when they are a `key-string`. `ip authentication key-chain` is treated as a name.
- Classic autonomous-AP `wpa-psk` lines are removed. Catalyst 9800 `security wpa psk set-key` syntax is not.
- One admin, and the login lockout is per process. There is no per-config delete.
