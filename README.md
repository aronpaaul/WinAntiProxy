# WinAntiProxy

Плагин для Minecraft (Paper/Spigot + Velocity/Bungee) для детекта прокси/VPN и фильтрации по странам/ASN.

## Возможности
- Детект по публичным спискам прокси (IP/CIDR/IP:порт).
- Оффлайн блок по странам (GeoLite2-Country.mmdb).
- Оффлайн блок по ASN/организации (GeoLite2-ASN.mmdb).
- Внешний интеллект (IPQualityScore / ProxyCheck) для VPN/Proxy/Residential (по желанию).
- Действие при детекте: кик или перевод на хаб.
- Все настройки в `config.yml`.

## Требования
- Java 8-21
- Paper/Spigot 1.16.5+ (api-version 1.16)
- Velocity/Bungee (если хотите кикать игроков в хаб не через Bukkit, а через BungeeCord)

## Установка
1. Сборка:
   ```bash
   mvn -DskipTests package
   ```
2. Закиньте `WinAntiProxy-*.jar` в папку `plugins`.
3. Запустите сервер, отредактируйте `config.yml`.
4. Если нужен оффлайн блок по странам/ASN — положите базы в `plugins/WinAntiProxy/`:
   - `GeoLite2-Country.mmdb`
   - `GeoLite2-ASN.mmdb`

## Где взять GeoLite2 базы
1. Зарегистрируйтесь в MaxMind и подключите GeoLite.
2. В личном кабинете откройте `GeoIP / GeoLite → Download Files` и скачайте:
   - GeoLite2 Country (MMDB)
   - GeoLite2 ASN (MMDB)
   - Либо же возьмите базы с GitHub репозитория.

Ссылки:
```text
https://www.maxmind.com/en/geolite2/signup
https://www.maxmind.com/en/account/geoip/downloads
https://github.com/P3TERX/GeoLite.mmdb
```

## Конфигурация (пример)
```yaml
proxy:
  action: "HUB"
  hub-server: "hub"
  message: "&cОтключите VPN или прокси и попробуйте зайти еще раз"

geoip:
  enabled: true
  mmdb-path: "GeoLite2-Country.mmdb"
  allow-country-codes: [RU, UA, BY, KZ, UZ, KG, TJ, TM, AZ, AM, GE, MD, LV, LT, EE, DE, PL]

asn:
  enabled: true
  mmdb-path: "GeoLite2-ASN.mmdb"
  block-asn: [13335]
  block-org-contains: ["cloudflare"]

intel:
  enabled: false
  provider: "ipqualityscore"
  api-key: ""
```

## Как работает детект
Порядок проверок:
1. Публичные списки (IP/CIDR/IP:порт)
2. Оффлайн GeoIP (страны)
3. Оффлайн ASN/ORG (например ASN 13335 / Cloudflare)
4. Внешний интеллект (если включен)

## Внешний интеллект (опционально)
Поддерживаются:
- IPQualityScore (IPQS)
- ProxyCheck

Включается через `intel.enabled: true` и `intel.api-key`.