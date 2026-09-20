# happ-relay-vercel

Релей подписки на Vercel: устройства подключаются к нему, а он запрашивает настоящую подписку с одним фиксированным идентификатором (x-hwid, User-Agent и т.д.). Панель видит одно устройство.

## Деплой

1. Vercel → Add New → Project → импортировать этот репозиторий (Framework Preset: Other).
2. Project → Settings → Environment Variables → добавить:
   - `PANEL_BASE` — адрес панели без токена
   - `HWID`, `USER_AGENT`, `DEVICE_OS`, `VER_OS`, `DEVICE_MODEL` — идентичность
3. Project → Settings → Domains → добавить свой домен, A-запись `76.76.21.21` **только** (без AAAA — критично для сетей с битым IPv6).

Проверка: `https://домен/vx42Kq9m/health` → `{"status":"ok"}`, затем `https://домен/vx42Kq9m/s/<токен>` → содержимое подписки.

## Переменные для WhiteNet (пример)

| Имя | Значение |
|---|---|
| `PANEL_BASE` | `https://sub.whitenet.online` |
| `HWID` | `74099e31-a84c-490c-9036-1104593e3754` |
| `USER_AGENT` | `Happ/2.7.0/Windows/2604031533607` |
| `DEVICE_OS` | `Windows` |
| `VER_OS` | `10.0.26100` |
| `DEVICE_MODEL` | `Z790 AORUS ELITE AX` |

## Ссылка для устройств

`https://<домен>/vx42Kq9m/s/<токен>` — префикс `vx42Kq9m` меняется в `vercel.json`.
