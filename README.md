# scripts

## diagnose_subscription.py

Read-only диагностика: сверяет то, что панель отдаёт в подписке, с тем, что
реально настроено на живых xray-нодах. Отвечает на «почему у клиента нет пинга».

Запускается внутри контейнера `brain` — там есть `DATABASE_URL`, `cryptography`,
`httpx` и сетевой доступ к Cell-агентам нод (их порт открыт только для Brain).
Ничего не меняет: только `SELECT` из БД и `GET /config/raw` + `GET /users` на нодах.

```bash
cd /opt/vgx3d
curl -fsSL https://raw.githubusercontent.com/rklm-it/scripts/main/diagnose_subscription.py -o /root/diag.py

# все инбаунды всех активных нод
docker compose exec -T brain python3 - < /root/diag.py

# + проверка, что UUID конкретного юзера реально добавлен на его ноды
docker compose exec -T brain python3 - < /root/diag.py <username|telegram_id|sub_token|uuid>
```

### Что проверяется по каждому инбаунду

| Проверка | Что значит провал |
|---|---|
| TCP-порт | `timeout` — фильтруется фаерволом (ufw / firewall хостера); `refused` — xray не слушает |
| TLS с нужным SNI | Reality проксирует чужой ClientHello на dest, поэтому валидный сертификат = инбаунд живой и dest достижим с ноды |
| `pbk` | `public_key` из БД против `derive(privateKey)` с ноды. Не совпал = ключи скопированы с другой панели, Reality-ключи у каждой ноды свои |
| `short_id`, SNI | нет в `shortIds` / `serverNames` на ноде → Reality отклонит соединение |
| порт БД ↔ нода | разошлись = push инбаунда не применился |
| UUID юзера в `clients` | нет = sync не прошёл, нужен «Resync users» |

В конце вывода — сводка и что нажимать по каждому типу проблемы.
