# Geo blocking

Geo blocking is configured per proxy host. It requires MaxMind GeoLite2 databases (see [GeoIP setup](#geoip-setup)).

It also has a fail-closed mode, custom response codes and bodies, and trusted proxy support. The defaults for every host are on the **Geo blocking** page (`/geo-blocking`, under Security events in the sidebar; [settings.md](settings.md)), and L4 proxy hosts have geo blocking of their own. [Access lists](access-lists.md) can allow or deny by country, continent and AS number too.

## Rule types

| Type | Example | Description |
|------|---------|-------------|
| Country | `DE` | ISO 3166-1 alpha-2 country code |
| Continent | `EU` | `AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA` |
| ASN | `64496` | Autonomous System Number |
| CIDR | `203.0.113.0/24` | IP range in CIDR notation |
| IP | `203.0.113.10` | Exact IP address |

Rules can be **block** or **allow**. Allow rules win over block rules, so you can block a continent and allow specific IPs or ASNs through.

## GeoIP setup

Geo blocking requires MaxMind GeoLite2 Country and/or ASN databases. The stack does not download them for you; put them in the `geoip-data` volume:

1. Register for a free MaxMind account at [maxmind.com](https://www.maxmind.com/)
2. Download the GeoLite2 databases (the `GeoLite2-Country` and `GeoLite2-ASN` `.mmdb` files)
3. Copy them into the volume, as root (the volume belongs to the container user):
   ```bash
   # Docker
   docker run --rm -v ingressi_geoip-data:/geoip -v "$PWD":/tmp docker.io/library/alpine:latest \
     sh -c "cp /tmp/GeoLite2-Country.mmdb /tmp/GeoLite2-ASN.mmdb /geoip/ && chown 10000:10000 /geoip/*.mmdb"
   # Podman
   podman run --rm -v ingressi_geoip-data:/geoip -v "$PWD":/tmp docker.io/library/alpine:latest \
     sh -c "cp /tmp/GeoLite2-Country.mmdb /tmp/GeoLite2-ASN.mmdb /geoip/ && chown 10000:10000 /geoip/*.mmdb"
   ```
   The volume name depends on the project directory: `docker volume ls` (or `podman volume ls`) shows it.

Caddy and the dashboard read the databases from the `geoip-data` volume and pick up a changed file within a minute; a restart is not needed.
