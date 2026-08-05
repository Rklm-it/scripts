#!/usr/bin/env python3
"""Сравнение нод: почему на одной клиенты работают, а на других «n/a».

Запускается ВНУТРИ контейнера brain, только читает:

    cd /opt/nexus
    docker compose exec -T brain python3 -u - < /root/compare.py
    docker compose exec -T brain python3 -u - < /root/compare.py <uuid_или_username>

Нужен, когда diagnose_subscription.py уже показал, что ссылки валидны
(pbk/short_id/порты/часы сходятся), а у клиента всё равно нет пинга. Тогда
проблема не в подключении, а в том, что происходит ПОСЛЕ handshake:

  • routing — правила с прошлой панели могут гнать всё в blocked
  • DNS      — недоступный резолвер: коннект есть, запросы клиента умирают
  • outbounds — нет direct/freedom, или дефолт уехал в relay/warp
  • geosite  — правила ссылаются на категории, а файла нет
  • egress   — сама нода не видит интернет
  • xray-логи — что xray говорит про соединения этого юзера

Смысл вывода — не абсолютные значения, а РАЗНИЦА между нодой, которая
работает, и теми, которые нет.
"""
import asyncio
import sys

sys.path.insert(0, "/app")

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

from sqlalchemy import select                       # noqa: E402

from app.db.session import async_session            # noqa: E402
from app.models.server import Server                # noqa: E402
from app.services.node_client import NodeClient     # noqa: E402

G, R, Y, B, N = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m"


async def safe(coro, default=None):
    try:
        return await coro
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {str(e)[:120]}"} if default is None else default


def fmt_outbounds(config: dict) -> str:
    obs = config.get("outbounds") or []
    if not obs:
        return f"{R}НЕТ OUTBOUND'ОВ — xray не сможет никуда отправить трафик{N}"
    parts = []
    for i, ob in enumerate(obs):
        tag = ob.get("tag") or "?"
        proto = ob.get("protocol") or "?"
        mark = " ←default" if i == 0 else ""
        parts.append(f"{tag}/{proto}{mark}")
    return ", ".join(parts)


def fmt_routing(config: dict) -> list[str]:
    out: list[str] = []
    routing = config.get("routing") or {}
    rules = routing.get("rules") or []
    domain_strategy = routing.get("domainStrategy", "—")
    out.append(f"routing: правил {len(rules)}, domainStrategy={domain_strategy}")

    blocked = [r for r in rules if (r.get("outboundTag") or "") in ("blocked", "block")]
    if blocked:
        out.append(f"  {Y}правил в blocked: {len(blocked)}{N}")
    # Правило-catch-all в blocked = всё, кроме явных исключений, режется
    for r in rules:
        tag = (r.get("outboundTag") or "")
        keys = {k for k in r.keys() if k not in ("type", "outboundTag")}
        if tag in ("blocked", "block") and not keys:
            out.append(f"  {R}CATCH-ALL в blocked: правило без условий режет ВСЁ{N}")
        if tag in ("blocked", "block") and keys == {"network"}:
            out.append(f"  {R}CATCH-ALL в blocked по network={r.get('network')} "
                       f"— режет весь {r.get('network')}-трафик{N}")
    # Тег, которого нет среди outbound'ов — xray дропает такие соединения.
    # НО: тег из блока `api` (stats-сервис) настоящим outbound'ом не является
    # и резолвится самим xray — его исключаем, иначе ложная тревога.
    ob_tags = {(ob.get("tag") or "") for ob in (config.get("outbounds") or [])}
    api_tag = ((config.get("api") or {}).get("tag") or "")
    if api_tag:
        ob_tags.add(api_tag)
    unknown = sorted({(r.get("outboundTag") or "") for r in rules} - ob_tags - {""})
    if unknown:
        out.append(f"  {R}правила ссылаются на несуществующие outbound: {unknown}{N}")
    return out


def fmt_dns(config: dict) -> str:
    dns = config.get("dns") or {}
    servers = dns.get("servers") or []
    if not servers:
        return "dns: не задан (xray берёт системный) — ок"
    flat = []
    for s in servers:
        flat.append(s if isinstance(s, str) else str(s.get("address", s)))
    return f"dns: {', '.join(flat[:6])}"


def log_lines(resp) -> list[str]:
    """Строки лога из ответа Cell.

    Cell отдаёт {"service": ..., "lines": [...]} (cell/agent/main.py:2040).
    Возвращаем (строки, доступен_ли_лог): файла может не быть вовсе —
    xray по умолчанию пишет только loglevel=warning в journal, access-лог
    не включён, и тогда «ноль соединений» ничего не значит.
    """
    if not isinstance(resp, dict):
        return []
    lines = resp.get("lines")
    if isinstance(lines, list):
        return [str(l) for l in lines]
    raw = resp.get("logs") or resp.get("output") or ""
    return str(raw).splitlines()


def log_missing(lines: list[str]) -> bool:
    return (not lines) or any("нет файла" in l or "No such file" in l for l in lines)


def count_geosite_rules(config: dict) -> int:
    n = 0
    for r in (config.get("routing") or {}).get("rules") or []:
        for d in (r.get("domain") or []):
            if isinstance(d, str) and d.startswith(("geosite:", "ext:")):
                n += 1
    return n


async def dump_node(srv: Server, ident: str) -> None:
    print(f"\n{B}=== {srv.name} ({srv.ip_address}) ==={N}")
    async with NodeClient(srv) as node:
        config = await safe(node.get_raw_config())
        if not isinstance(config, dict) or "_error" in config:
            print(f"  {R}Cell недоступен: {config}{N}")
            return

        ver = await safe(node.get_xray_version())
        geo = await safe(node.get_geosite_info())
        egress = await safe(node.test_outbound("direct", "https://www.google.com/generate_204"))
        errlog = await safe(node.get_logs("xray", 200))
        acclog = await safe(node.get_logs("xray-access", 200))

    if isinstance(ver, dict):
        print(f"  xray: {ver.get('version') or ver.get('raw', '')[:40] or ver}")
    print(f"  outbounds: {fmt_outbounds(config)}")
    for line in fmt_routing(config):
        print(f"  {line}")
    print(f"  {fmt_dns(config)}")

    geosite_rules = count_geosite_rules(config)
    if geosite_rules:
        info = geo if isinstance(geo, dict) else {}
        print(f"  geosite: правил с geosite/ext {geosite_rules}, на ноде {info}")

    # egress: это запрос ИЗ АГЕНТА, не через xray (Cell игнорирует tag) —
    # проверяет только, что у ноды вообще есть интернет и DNS.
    if isinstance(egress, dict) and egress.get("status") == "ok":
        print(f"  egress ноды (агент→интернет): ok {egress.get('latency_ms')}ms")
    else:
        print(f"  {R}egress ноды: {egress}{N}")

    # xray error log: тут видно «invalid request», «unable to resolve» и т.п.
    err_lines = log_lines(errlog)
    lines = [l for l in err_lines
             if any(k in l.lower() for k in
                    ("error", "failed", "invalid", "rejected", "unable", "refused"))]
    if lines:
        print(f"  {Y}xray error log (последние){N}")
        for l in lines[-6:]:
            print(f"    {l[:200]}")

    # access log: были ли реальные подключения и чьи.
    # Внимание: по умолчанию xray пишет только loglevel=warning и access-лога
    # НЕТ вообще (cell-setup.sh:426). Пустой лог ≠ «клиенты не доходят».
    acc_lines = log_lines(acclog)
    if log_missing(acc_lines):
        print(f"  {Y}access log недоступен (xray его не пишет — "
              f"log.access не настроен). Судить о числе подключений нельзя{N}")
    else:
        acc = [l for l in acc_lines if "accepted" in l.lower()]
        mine = [l for l in acc if ident and ident.lower() in l.lower()]
        print(f"  access log: принятых соединений {len(acc)}"
              + (f", из них этого юзера {len(mine)}" if ident else ""))
        for l in (mine or acc)[-3:]:
            print(f"    {l[:200]}")


async def main() -> None:
    ident = sys.argv[1] if len(sys.argv) > 1 else ""

    async with async_session() as db:
        if ident and "-" not in ident:
            from app.models.user import User
            res = await db.execute(select(User).where(User.username == ident))
            u = res.scalars().first()
            if u:
                ident = str(u.vless_uuid)
                print(f"{B}Юзер {sys.argv[1]} → uuid {ident}{N}")

        servers = list((await db.execute(
            select(Server).where(Server.is_active == True)  # noqa: E712
        )).scalars().all())

        for srv in servers:
            try:
                await asyncio.wait_for(dump_node(srv, ident), timeout=90)
            except asyncio.TimeoutError:
                print(f"  {R}таймаут 90с на {srv.name}{N}")
            except Exception as e:
                print(f"  {R}{srv.name}: {type(e).__name__}: {str(e)[:150]}{N}")

    print(f"""
{Y}Как читать:{N} сравни ноду, где клиенты работают, с теми, где нет.
Значимая разница обычно в одном из трёх мест — routing (правила с прошлой
панели, catch-all в blocked, ссылки на несуществующие outbound), dns
(недоступный резолвер: коннект проходит, запросы клиента умирают) или
outbounds (нет direct, дефолтом стоит relay/warp).""")


if __name__ == "__main__":
    asyncio.run(main())
