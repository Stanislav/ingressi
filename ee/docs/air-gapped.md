# Air-gapped installs

An offline install bundle for hosts that cannot reach GitHub's container registry or the Internet. Code: `ee/scripts/airgap-bundle.sh` (Elastic License 2.0).

## Building a bundle

On a machine with Docker, Internet access and [cosign](https://docs.sigstore.dev/cosign/system_config/installation/), check out the release tag and run:

```bash
ee/scripts/airgap-bundle.sh --version 2.0.0 --platform linux/amd64
```

The script:

1. Pulls the images the default stack runs, for the target platform: `ingressi-web`, `ingressi-caddy` and `ingressi-l4-port-manager` at the release tag, and the ClickHouse and Docker socket proxy images exactly as `docker-compose.yml` names them. The GeoLite2 databases are not part of the stack; copy them into the `geoip-data` volume ([geo-blocking.md](../../documentation/geo-blocking.md#geoip-setup)).
2. Verifies the cosign signature of each Ingressi image against the release workflow. It stops if one is missing or invalid.
3. Writes `dist/ingressi-airgap-<version>-<platform>.tar` with its SHA-256 next to it.

| Option | Default | Meaning |
| --- | --- | --- |
| `--version` | (required) | Release tag of the Ingressi images |
| `--platform` | `linux/amd64` | Platform of the target host (`linux/arm64` for ARM servers) |
| `--output` | `./dist` | Where to write the bundle |
| `--image-prefix` | `ghcr.io/ingres-si/ingressi` | Registry and name prefix of the Ingressi images, for a mirror |
| `--no-pull` | off | Use images already present locally |
| `--skip-verify` | off | Do not check signatures (for images you built yourself) |

The bundle contains:

- `images.tar.gz`: every image;
- `docker-compose.yml`, pinned to the release's Ingressi images, and the ClickHouse config file it mounts;
- `.env.example`;
- `install.sh`;
- `manifest.json`: version, platform, whether signatures were verified, and each image's registry digest;
- `SHA256SUMS` over all of the above.

## Installing

Copy the `.tar` and its `.sha256` file to the target host by your approved transfer process, then:

```bash
sha256sum -c ingressi-airgap-2.0.0-linux-amd64.tar.sha256
tar -xf ingressi-airgap-2.0.0-linux-amd64.tar
cd ingressi-airgap-2.0.0-linux-amd64
./install.sh
```

`install.sh` checks `SHA256SUMS`, loads the images and creates `.env` from `.env.example` (mode 600) if there is none. Fill in `SESSION_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` and `CLICKHOUSE_PASSWORD`, and start the stack:

```bash
docker compose up -d
```

To upgrade, build a bundle of the new release, run its `install.sh` in its own directory, copy your `.env` over, and run `docker compose up -d` there. The data lives in Docker volumes, so it carries over. The compose project name comes from the directory name: pass the old one with `-p` (for example `docker compose -p ingressi-airgap-2-0-0-linux-amd64 up -d`), or keep using one fixed directory and copy the new bundle's files into it.

## Running without Internet access

| Function | Offline approach |
| --- | --- |
| Certificates | Automatic Let's Encrypt or ZeroSSL issuance needs Internet access. Use your internal ACME CA (**Certificate settings → Certificate authority → Custom ACME directory**, with its root certificate), import certificates, or issue them from the built-in CA. |
| GeoIP blocking | Copy `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` into the `geoip-data` volume (for example `docker run --rm -v <project>_geoip-data:/data -v "$PWD":/src alpine cp /src/GeoLite2-Country.mmdb /src/GeoLite2-ASN.mmdb /data/`) and refresh them with each bundle. |
| AI analyst | Point it at a model server on your network (any OpenAI-compatible endpoint such as vLLM or Ollama). |
| Alerts and digests | Use your internal SMTP relay and webhook endpoints. |
