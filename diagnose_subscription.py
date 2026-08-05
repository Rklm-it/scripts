#!/usr/bin/env python3
"""Сверка подписки с живыми нодами — «почему у клиента нет пинга».

Запускается ВНУТРИ контейнера brain (там есть DATABASE_URL, cryptography,
httpx и сетевой доступ к Cell-нодам, чей порт открыт только для Brain).
Ничего не меняет — только читает.

    cd /opt/vgx3d
    docker compose exec -T brain python3 - < scripts/diagnose_subscription.py
    docker compose exec -T brain python3 - < scripts/diagnose_subscription.py <username>

Без аргумента проверяет только инбаунды (ключи/порты/SNI/доступность).
С username|telegram_id|sub_token дополнительно проверяет, что UUID этого
юзера реально добавлен на каждую его ноду.

Что проверяется по каждому инбаунду:
  • TCP-порт снаружи      — timeout = фильтруется фаерволом, refused = xray не слушает
  • TLS с нужным SNI      — Reality проксирует чужой ClientHello на dest, поэтому
                            валидный сертификат = инбаунд живой И dest достижим с ноды
  • pbk                   — public_key из БД против derive(privateKey) с ноды.
                            НЕ СОВПАДАЕТ = настройки скопированы с другой панели:
                            Reality-ключи у каждой ноды свои
  • short_id / SNI        — есть ли они в shortIds / serverNames на ноде
  • порт БД ↔ порт ноды   — разошлись = push не применился
  • UUID юзера в clients  — нет = sync не прошёл
"""
import asyncio
import base64
import socket
import ssl
import sys

import httpx
from sqlalchemy import select, text

sys.path.insert(0, "/app")

# `docker compose exec -T` не даёт TTY → Python буферизует stdout блоками,
# и во время проб (5с на TCP, 7с на TLS × число инбаундов) кажется, что
# скрипт повис. Переводим на построчный вывод — прогресс виден сразу.
try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

from app.db.session import async_session          # noqa: E402
from app.models.inbound import Inbound            # noqa: E402
from app.models.server import Server              # noqa: E402

REALITY_PROTOS = {"reality", "reality_grpc", "vless_xhttp"}
UDP_PROTOS = {"hysteria2", "vless_mkcp", "vless_xdns", "vless_xicmp"}
CDN_PROTOS = {"vless_xhttp_cdn", "vless_ws_cdn", "vless_httpupgrade_cdn"}

G, R, Y, B, N = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m"


def derive_public_key(private_key_b64: str) -> str:
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        padded = private_key_b64 + "=" * (-len(private_key_b64) % 4)
        priv = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(padded))
        return base64.urlsafe_b64encode(
            priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode().rstrip("=")
    except Exception:
        return ""


async def tcp_probe(host: str, port: int, timeout: float = 5.0) -> str:
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        return "open"
    except asyncio.TimeoutError:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except Exception as e:
        return f"{type(e).__name__}"
    finally:
        if writer is not None:
            writer.close()


def _tls_sync(host: str, port: int, sni: str) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or None) as tls:
                der = tls.getpeercert(binary_form=True) or b""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        cert = x509.load_der_x509_certificate(der)
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return f"cert:{attrs[0].value}" if attrs else "cert:?"
    except Exception as e:
        return f"fail:{type(e).__name__}"


async def tls_probe(host: str, port: int, sni: str) -> str:
    return await asyncio.to_thread(_tls_sync, host, port, sni)


async def node_get(srv: Server, path: str) -> dict | list | None:
    """Запрос к Cell-агенту ноды тем же способом, что делает Brain."""
    url = f"http://{srv.ip_address}:{srv.api_port}{path}"
    headers = {"Authorization": f"Bearer {srv.api_token}"}
    try:
        async with httpx.AsyncClient(timeout=15) as cl:
            r = await cl.get(url, headers=headers)
        if r.status_code != 200:
            print(f"    {R}Cell {path} → HTTP {r.status_code}{N}")
            return None
        return r.json()
    except Exception as e:
        print(f"    {R}Cell {path} недоступен: {type(e).__name__}: {str(e)[:120]}{N}")
        return None


async def node_clock_skew(srv: Server) -> float | None:
    """Расхождение часов ноды с Brain'ом, секунды (по HTTP-заголовку Date).

    Reality завязан на время: клиент шлёт в ClientHello метку, xray её
    проверяет, и при уплывших часах ноды РЕАЛЬНЫЕ клиенты получают отказ —
    а TLS-проба этого не видит, потому что она не аутентифицируется и её
    просто проксируют на dest. Поэтому skew проверяем отдельно.
    """
    from email.utils import parsedate_to_datetime
    url = f"http://{srv.ip_address}:{srv.api_port}/health"
    try:
        async with httpx.AsyncClient(timeout=10) as cl:
            r = await cl.get(url, headers={"Authorization": f"Bearer {srv.api_token}"})
        raw = r.headers.get("date")
        if not raw:
            return None
        import datetime as _dt
        node_time = parsedate_to_datetime(raw)
        now = _dt.datetime.now(_dt.timezone.utc)
        return (node_time - now).total_seconds()
    except Exception:
        return None


def endpoint(srv: Server, ib: Inbound) -> tuple[str, int, str]:
    cfg = ib.config_json or {}
    if ib.protocol in CDN_PROTOS:
        return (cfg.get("cdn_host") or "").strip(), 443, "tcp"
    if ib.protocol == "hysteria2":
        return ((srv.hysteria_domain or "").strip() or srv.ip_address,
                ib.listen_port, "udp")
    if ib.protocol == "vless_ws":
        return ((cfg.get("host") or "").strip() or srv.ip_address,
                ib.listen_port, "tcp")
    return srv.ip_address, ib.listen_port, ("udp" if ib.protocol in UDP_PROTOS else "tcp")


def check_inbound(srv, ib, node_ib: dict | None, user_uuid: str = "") -> list[str]:
    """Сверка БД ↔ живой xray-конфиг ноды. Возвращает список проблем."""
    cfg = ib.config_json or {}
    problems: list[str] = []

    # Hysteria2 — standalone-бинарь, а не xray-инбаунд: в xray-конфиге его
    # нет и быть не должно. Сверять тут нечего (юзеры hy2 проверяются
    # отдельно, по Cell /users), иначе получаем ложное «push не прошёл».
    if ib.protocol == "hysteria2":
        return []

    if node_ib is None:
        return [f"на ноде НЕТ инбаунда с tag='{ib.tag}' — push не прошёл"]

    if node_ib.get("port") != ib.listen_port:
        problems.append(
            f"порт разошёлся: в БД {ib.listen_port}, на ноде {node_ib.get('port')}"
        )

    clients = (node_ib.get("settings") or {}).get("clients") or []
    # VLESS-клиент опознаётся по `id`, а Shadowsocks-2022 — по `password`
    # (UUID там превращается в ключ), при этом Cell всегда кладёт UUID ещё и
    # в `email` для статистики. Смотрим все три поля, иначе на ss2022-инбаунде
    # получаем ложное «UUID не в clients».
    ids: set[str] = set()
    for c in clients:
        for key in ("id", "email", "password"):
            val = c.get(key)
            if isinstance(val, str) and val:
                ids.add(val.lower())
    if user_uuid and ib.protocol != "hysteria2" and user_uuid.lower() not in ids:
        problems.append(f"UUID юзера НЕ в clients (на ноде {len(clients)} клиентов) — sync не прошёл")

    if ib.protocol in REALITY_PROTOS:
        ss = node_ib.get("streamSettings") or {}
        rs = ss.get("realitySettings") or {}
        node_priv = rs.get("privateKey") or ""
        node_pub = derive_public_key(node_priv) if node_priv else ""
        db_pub = (cfg.get("public_key") or "").rstrip("=")
        if not db_pub:
            problems.append("в БД нет public_key — ссылка не попадёт в подписку")
        elif node_pub and node_pub != db_pub:
            problems.append(
                f"PBK НЕ СОВПАДАЕТ: подписка отдаёт {db_pub[:20]}…, "
                f"нода ждёт {node_pub[:20]}… → ключи скопированы с другой панели"
            )
        db_sids = cfg.get("short_ids") or [""]
        db_sid = db_sids[0] if db_sids else ""
        node_sids = [str(s) for s in (rs.get("shortIds") or [])]
        if db_sid and node_sids and db_sid not in node_sids:
            problems.append(f"short_id '{db_sid}' нет на ноде ({node_sids})")
        sni = cfg.get("sni", "www.google.com")
        node_names = [str(s) for s in (rs.get("serverNames") or [])]
        if node_names and sni not in node_names:
            problems.append(f"SNI '{sni}' нет в serverNames ноды ({node_names[:3]})")

    return problems


async def find_user(db, ident: str):
    """Юзер по username / telegram_id / sub_token / UUID — что дали, то и ищем."""
    import uuid as _uuid
    from app.models.user import User

    conds = [User.username == ident, User.sub_token == ident]
    if ident.isdigit():
        conds.append(User.telegram_id == int(ident))
    try:
        conds.append(User.vless_uuid == _uuid.UUID(ident))
    except ValueError:
        pass

    for cond in conds:
        res = await db.execute(select(User).where(cond))
        user = res.scalars().first()
        if user:
            return user
    return None


async def main() -> None:
    ident = sys.argv[1] if len(sys.argv) > 1 else ""
    total_problems = 0

    async with async_session() as db:
        user = None
        user_server_ids: set = set()
        if ident:
            user = await find_user(db, ident)
            if not user:
                print(f"{R}Юзер '{ident}' не найден (пробовал username, telegram_id, sub_token, UUID){N}")
                return
            rows = await db.execute(
                text("SELECT server_id FROM user_servers WHERE user_id = :uid"),
                {"uid": str(user.id)},
            )
            user_server_ids = {r[0] for r in rows.all()}
            print(f"{B}Юзер:{N} {user.username}  uuid={user.vless_uuid}  "
                  f"active={user.is_active}  blocked={user.is_blocked}  "
                  f"привязан к нодам: {len(user_server_ids)}\n")

        srv_rows = await db.execute(select(Server).where(Server.is_active == True))  # noqa: E712
        servers = list(srv_rows.scalars().all())

        for srv in servers:
            if user and srv.id not in user_server_ids:
                continue
            ib_rows = await db.execute(
                select(Inbound).where(Inbound.server_id == srv.id).order_by(Inbound.tag)
            )
            inbounds = [ib for ib in ib_rows.scalars().all() if ib.is_enabled and not ib.is_hidden]

            print(f"{B}=== {srv.name} ({srv.ip_address}) — инбаундов: {len(inbounds)} ==={N}")
            node_cfg = await node_get(srv, "/config/raw")
            node_users = await node_get(srv, "/users")
            if node_cfg is None:
                print(f"  {R}Cell-агент не ответил → проверь `systemctl status vpn-cell` "
                      f"на ноде и что порт {srv.api_port} открыт для этого Brain{N}\n")
                total_problems += 1
                continue

            skew = await node_clock_skew(srv)
            if skew is None:
                print(f"  {Y}часы ноды: не удалось прочитать (нет заголовка Date){N}")
            elif abs(skew) > 60:
                print(f"  {R}часы ноды разошлись с Brain'ом на {skew:+.0f}с — Reality "
                      f"отвергает клиентов при уплывших часах, ставь NTP: "
                      f"timedatectl set-ntp true{N}")
                total_problems += 1
            else:
                print(f"  часы ноды: {skew:+.1f}с — ок")

            hy_ids = set()
            if isinstance(node_users, dict):
                hy_ids = {str(u.get("uuid", "")).lower() for u in (node_users.get("users") or [])
                          if u.get("protocol") == "hysteria2"}

            by_tag = {i.get("tag"): i for i in (node_cfg.get("inbounds") or [])}

            for ib in inbounds:
                host, port, transport = endpoint(srv, ib)
                cfg = ib.config_json or {}
                sni = cfg.get("sni", "www.google.com")

                line = f"  {ib.tag:28} {ib.protocol:20} {host}:{port}/{transport}"
                probes = []
                if host and transport == "tcp":
                    tcp = await tcp_probe(host, port)
                    probes.append(f"tcp={tcp}")
                    if tcp == "open" and ib.protocol in REALITY_PROTOS:
                        probes.append(f"tls[{sni}]={await tls_probe(host, port, sni)}")
                else:
                    probes.append("tcp=skip(udp)")

                problems = check_inbound(srv, ib, by_tag.get(ib.tag),
                                         str(user.vless_uuid) if user else "")
                if user and ib.protocol == "hysteria2" and hy_ids and \
                        str(user.vless_uuid).lower() not in hy_ids:
                    problems.append("UUID юзера НЕ в списке Hysteria2 на ноде")
                if "tcp=timeout" in probes:
                    problems.append("порт не отвечает: фаервол (ufw / firewall хостера) "
                                    "или xray не слушает")
                if "tcp=refused" in probes:
                    problems.append("connection refused: на порту никто не слушает")
                if any(p.startswith("tls[") and "=fail" in p for p in probes):
                    problems.append("TLS не поднялся: dest/SNI недостижим С НОДЫ "
                                    "или инбаунд не Reality")

                mark = f"{G}OK{N}" if not problems else f"{R}FAIL{N}"
                print(f"{line}  {'  '.join(probes)}  [{mark}]")
                for p in problems:
                    print(f"      {R}→ {p}{N}")
                total_problems += len(problems)
            print()

    print(f"{B}Итого проблем: {total_problems}{N}")
    if total_problems:
        print(f"""
{Y}Что делать:{N}
  • «PBK НЕ СОВПАДАЕТ» / «short_id нет на ноде» → в панели у этого инбаунда
    нажми Push. Cell вернёт свои реальные ключи, и панель перезапишет
    public_key/short_ids в БД. Ключи Reality НЕЛЬЗЯ копировать между панелями.
  • «UUID юзера НЕ в clients» → на сервере нажми «Resync users».
  • «порт не отвечает» → на ноде: ufw allow <порт>/tcp (и то же в фаерволе
    хостера), затем systemctl status xray.
  • «на ноде НЕТ инбаунда с tag» → Push инбаунда.
  • «TLS не поднялся» → смени SNI/dest на домен, который реально открывается
    из страны ноды: curl -sI https://<sni> с самой ноды.""")


if __name__ == "__main__":
    asyncio.run(main())
