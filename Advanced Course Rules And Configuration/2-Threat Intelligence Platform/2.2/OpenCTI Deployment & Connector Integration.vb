OpenCTI Deployment & Connector Integration Guide

This guide provides the necessary steps to deploy the OpenCTI platform using Docker and configure the AlienVault OTX and Wazuh connectors.


🚀 1. Host Machine Preparation

Before starting, increase the memory map count required for the database dependencies:
# Run this on your host machine
sudo sysctl -w vm.max_map_count=1048575

# To make it permanent, add it to /etc/sysctl.conf
echo "vm.max_map_count=1048575" | sudo tee -a /etc/sysctl.conf

📂 2. Installation from GitHub

Clone the official OpenCTI Docker repository and prepare the environment file:

mkdir -p opencti
git clone https://github.com/OpenCTI-Platform/docker.git
cd docker

# Copy the sample environment file
cp .env.sample .env

🔑 3. Security & Environment Configuration
Generate Encryption Key

openssl rand -base64 32

Configure .env

Open the .env file and update the following critical variables:

OPENCTI_ENCRYPTION_KEY=PASTE_YOUR_KEY_HERE

###########################
# DEPENDENCIES            #
###########################
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=
SMTP_HOSTNAME=localhost
OPENSEARCH_ADMIN_PASSWORD=
ELASTIC_MEMORY_SIZE=4G

###########################
# COMMON                  #
###########################
XTM_COMPOSER_ID=8215614c-7139-422e-b825-b20fd2a13a23
COMPOSE_PROJECT_NAME=xtm

###########################
# OPENCTI                 #
###########################
OPENCTI_HOST=10.10.30.53
OPENCTI_PORT=8080
OPENCTI_EXTERNAL_SCHEME=http
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=
OPENCTI_ADMIN_TOKEN=4167f685-f888-438d-bda5-7ae75f995371
OPENCTI_HEALTHCHECK_ACCESS_KEY=09dd2ff4-1a62-4d88-b9b4-6ac868dc436c

###########################
# OPENCTI CONNECTORS      #
###########################
CONNECTOR_EXPORT_FILE_STIX_ID=dd817c8b-abae-460a-9ebc-97b1551e70e6
CONNECTOR_EXPORT_FILE_CSV_ID=7ba187fb-fde8-4063-92b5-c3da34060dd7
CONNECTOR_EXPORT_FILE_TXT_ID=ca715d9c-bd64-4351-91db-33a8d728a58b
CONNECTOR_IMPORT_FILE_STIX_ID=72327164-0b35-482b-b5d6-a5a3f76b845f
CONNECTOR_IMPORT_DOCUMENT_ID=c3970f8a-ce4b-4497-a381-20b7256f56f0
CONNECTOR_IMPORT_FILE_YARA_ID=7eb45b60-069b-4f7f-83a2-df4d6891d5ec
CONNECTOR_IMPORT_EXTERNAL_REFERENCE_ID=d52dcbc8-fa06-42c7-bbc2-044948c87024
CONNECTOR_ANALYSIS_ID=4dffd77c-ec11-4abe-bca7-fd997f79fa36

###########################
# OPENCTI DEFAULT DATA    #
###########################
CONNECTOR_OPENCTI_ID=dd010812-9027-4726-bf7b-4936979955ae
CONNECTOR_MITRE_ID=8307ea1e-9356-408c-a510-2d7f8b28a0e2
CONNECTOR_WAZUH_ID=2e4d2f0c-6a1a-4c9f-9b5e-2b7b0e6d9e11


🛠️ 4. Connector Configuration

Add the following service blocks to your docker-compose.yml:
AlienVault OTX Connector

connector-alienvault:
    image: opencti/connector-alienvault:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=8bbae241-6289-4faf-b7d6-7503bed50bbc
      - CONNECTOR_NAME=AlienVault
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_SCOPE=alienvault
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT30M
      - ALIENVAULT_BASE_URL=https://otx.alienvault.com
      - ALIENVAULT_API_KEY=ChangeMe
      - ALIENVAULT_TLP=White
      - ALIENVAULT_CREATE_OBSERVABLES=true
      - ALIENVAULT_CREATE_INDICATORS=true
      - ALIENVAULT_PULSE_START_TIMESTAMP=2026-02-10T00:00:00Z
      - ALIENVAULT_REPORT_TYPE=threat-report
      - ALIENVAULT_REPORT_STATUS=New
      - ALIENVAULT_GUESS_MALWARE=false
      - ALIENVAULT_GUESS_CVE=false
      - ALIENVAULT_EXCLUDED_PULSE_INDICATOR_TYPES=FileHash-MD5,FileHash-SHA1
      - ALIENVAULT_ENABLE_RELATIONSHIPS=true
      - ALIENVAULT_ENABLE_ATTACK_PATTERNS_INDICATES=true
      - ALIENVAULT_FILTER_INDICATORS=false
      - ALIENVAULT_DEFAULT_X_OPENCTI_SCORE=50
      - ALIENVAULT_X_OPENCTI_SCORE_IP=60
      - ALIENVAULT_X_OPENCTI_SCORE_DOMAIN=70
      - ALIENVAULT_X_OPENCTI_SCORE_HOSTNAME=75
      - ALIENVAULT_X_OPENCTI_SCORE_EMAIL=70
      - ALIENVAULT_X_OPENCTI_SCORE_FILE=80
      - ALIENVAULT_X_OPENCTI_SCORE_URL=80
      - ALIENVAULT_X_OPENCTI_SCORE_MUTEX=60
      - ALIENVAULT_X_OPENCTI_SCORE_CRYPTOCURRENCY_WALLET=80
      - CONNECTOR_QUEUE_THRESHOLD=1000
    restart: always
    depends_on:
      opencti:
        condition: service_healthy


Wazuh Connector

connector-wazuh:
    image: ghcr.io/misje/opencti-wazuh-connector:latest
    restart: always
    environment:
      - TZ=UTC
      - USE_TZ=true
      - OPENCTI_URL=http://10.187.218.37:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_WAZUH_ID}
      - CONNECTOR_NAME=Wazuh
      - CONNECTOR_SCOPE=Artifact,Directory,Domain-Name,Email-Addr,Hostname,IPv4-Addr,IPv6-Addr,Mac-Addr,Network-Traffic,Process,StixFile,Url,User-Account,User-Agent,Windows-Registry-Key,Windows-Registry-Value-Type,Vulnerability,Indicator
      - CONNECTOR_AUTO=true
      - CONNECTOR_LOG_LEVEL=warning
      - CONNECTOR_EXPOSE_METRICS=true
      - WAZUH_APP_URL=https://10.187.218.21
      - WAZUH_OPENSEARCH_URL=https://10.10.20.51:9200
      - WAZUH_OPENSEARCH_USERNAME=cti_connector
      - WAZUH_OPENSEARCH_PASSWORD=hunter@19#20
      - WAZUH_OPENSEARCH_VERIFY_TLS=false
      - WAZUH_MAX_TLP=TLP:AMBER+STRICT
      - WAZUH_TLPS=TLP:AMBER+STRICT
    volumes:
      - /var/cache/wazuh
    depends_on:
      opencti:
        condition: service_healthy



🐳 5. Deployment & Verification
Start the Stack

docker compose up -d --build


Verify Connectivity

Ensure your firewall allows port 8080 and test the API response:

# Allow Firewall Port
sudo ufw allow 8080

# Verify OpenCTI Version via GraphQL
curl -k -X POST \
  -H "Authorization: Bearer 4167f685-f888-438d-bda5-7ae75f995371" \
  -H "Content-Type: application/json" \
  http://10.10.30.53:8080/graphql \
  -d '{"query": "{ about { version } }"}'



Verify Connectors

Check the logs to ensure the AlienVault connector is fetching data:

docker logs -f connector-alienvault


