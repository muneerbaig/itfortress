# Detection Rules Framework

**Owner:** IT Fortress Limited  
**Copyright:** © 2026 IT Fortress Limited. All rights reserved.

A structured repository for **SIEM detection content** with a focus on **Wazuh**-compatible rules, decoders, validation tooling, and operational documentation. Use it as a template or baseline for organizational threat detection engineering.

---

## Disclaimer

This project provides **detection logic and examples for security monitoring**. Rules and decoders may produce false positives or false negatives. **They do not guarantee detection of every attack.** Validate all content in non-production environments before deployment. See [LICENSE](LICENSE) and [docs/security_disclaimer.md](docs/security_disclaimer.md).

**License:** [Apache License 2.0](LICENSE) (recommended for broad collaboration while preserving patent and attribution clarity). Alternative: MIT if your organization standardizes on it.

---

## Features

- **Wazuh-aligned rule examples** — XML rules with documented IDs, levels, and groups.
- **Decoder samples** — Syslog-style and JSON-oriented parsing patterns.
- **Automation scripts** — Deploy rules to a manager, validate XML, and inject test logs.
- **Lifecycle documentation** — Authoring, testing, promotion, and integration guidance.
- **PDF-ready guide** — Export [`pdf/Detection_Engineering_Guide.md`](pdf/Detection_Engineering_Guide.md) to PDF for internal training.

---

## Installation

### Prerequisites

- Wazuh manager (or lab VM) with access to `local_rules.xml` / custom rule files and decoder configuration (version aligned to your deployment).
- Python 3.10+ (for validation and helper scripts).
- `bash` (Git Bash or WSL on Windows) for shell examples.

### Clone and setup

```bash
git clone https://github.com/<your-org>/detection-rules-framework.git
cd detection-rules-framework
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt   # if present; optional for XML linting
```

Copy rule and decoder fragments into your Wazuh manager following [docs/rules_creation_guide.md](docs/rules_creation_guide.md) and [docs/decoders_guide.md](docs/decoders_guide.md), or use [scripts/deploy_rules.sh](scripts/deploy_rules.sh) as a reference for your own pipeline.

---

## Usage examples

### Validate local rule XML (syntax check)

```bash
python scripts/validate_rules_xml.py --path rules/sample_basic_rule.xml
```

### Deploy rules (example — adjust paths and service names)

```bash
chmod +x scripts/deploy_rules.sh
sudo ./scripts/deploy_rules.sh --dry-run
```

### Test log pipeline (inject sample line)

```bash
chmod +x scripts/test_log_injection.sh
./scripts/test_log_injection.sh samples/sample_auth.log
```

---

## Repository layout

| Path | Purpose |
|------|---------|
| `rules/` | Wazuh-style XML detection rules (modular examples). |
| `decoders/` | Decoder definitions and JSON-field extraction examples. |
| `scripts/` | Deployment, validation, and log-testing automation. |
| `samples/` | Representative log lines and payloads for testing. |
| `docs/` | Authoring guides, lifecycle, testing, integration, disclaimer. |
| `pdf/` | Long-form **Detection Engineering Guide** (Markdown → PDF). |

---

## Sample rule snippet (Wazuh XML)

```xml
<!-- Example: high-signal SSH brute-force correlation (illustrative) -->
<group name="itfortress,authentication,ssh,">
  <rule id="100001" level="10">
    <decoded_as>sshd</decoded_as>
    <match>Failed password</match>
    <description>IT Fortress: SSH authentication failure observed.</description>
    <group>authentication_failed,sshd,</group>
  </rule>
</group>
```

See [rules/sample_basic_rule.xml](rules/sample_basic_rule.xml) and [rules/sample_advanced_rules.xml](rules/sample_advanced_rules.xml) for complete examples.

---

## Documentation index

| Document | Description |
|----------|-------------|
| [docs/rules_creation_guide.md](docs/rules_creation_guide.md) | Rule format, IDs, severity, groups, best practices. |
| [docs/decoders_guide.md](docs/decoders_guide.md) | Syslog and JSON decoding patterns. |
| [docs/rule_lifecycle.md](docs/rule_lifecycle.md) | Draft → test → prod workflow. |
| [docs/testing_and_validation.md](docs/testing_and_validation.md) | QA and regression testing. |
| [docs/integration_threat_intel.md](docs/integration_threat_intel.md) | Threat intel and API integration notes. |
| [pdf/Detection_Engineering_Guide.md](pdf/Detection_Engineering_Guide.md) | Printable / PDF export guide. |

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security-sensitive issues should be reported according to your organization’s disclosure policy.

---

## Copyright

© 2026 **IT Fortress Limited**. All rights reserved.

---

## Yeti Docker (yeti-docker) Setup

Install The Yeti Form GIt 

```bash
git clone https://github.com/yeti-platform/yeti-docker
cd yeti-docker/prod
```

Create the TOken of hash 

```bash
openssl rand -hex 32
```

Once token created added in .env

```bash
YETI_AUTH_SECRET_KEY=7f3a8b2c1d4e5f6a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2
```

Start Yeti:

```bash
docker compose up -d
```

This starts Yeti and exposes the web UI on http://0.0.0.0:80

Create an admin user and log in:

```bash
docker compose run --rm api create-user admin myStrongPass --admin
```

To add the Abuseipdb Api keys:

```bash
docker exec -it yeti-task bash
```

Update and install the packages

```bash
apt-get update
apt install nano
```

go to directories cd /app/plugins/analytics/public/ 

```bash
nano abuseipdb
```

```python
def run(self):
        # REPLACE THE OLD LINE WITH THIS ONE:
        api_key = "PASTE_YOUR_LONG_API_KEY_HERE"
```

Yeti Platform - Installation & AbuseIPDB Integration

This repository contains the deployment steps for the Yeti threat intelligence platform using Docker, including manual plugin configuration for AbuseIPDB.
Installation from GitHub

Clone the official repository and enter the production environment:

git clone https://github.com/yeti-platform/yeti-docker
cd yeti-docker/prod

Security Configuration

Generate a unique 32-byte hex token for authentication:
openssl rand -hex 32

Add your generated token to the .env file:

YETI_AUTH_SECRET_KEY=7f3a8b2c1d4e5f6a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2

Deployment

Start the Yeti stack in detached mode:

docker compose up -d

Access: Once the containers are running, the Web UI is available at http://0.0.0.0:80

Create Admin User

Generate your credentials to log into the dashboard:

docker compose run --rm api create-user admin myStrongPass --admin

AbuseIPDB API Key Integration

To manually add the AbuseIPDB API key, you must enter the task container and modify the plugin source.

    Access the task container:

    docker exec -it yeti-task bash

Update packages and install editor:

apt-get update
apt install nano -y

Navigate to the plugin directory:

cd /app/plugins/analytics/public/

Edit the AbuseIPDB plugin file:

nano abuseipdb

Update the API key line:
Locate the run function and replace the key variable:

def run(self):
    # REPLACE THE OLD LINE WITH THIS ONE:
    api_key = "PASTE_YOUR_LONG_API_KEY_HERE"


exit

Restart the docker yeti-tasks:
 docker restart yeti-tasks..
