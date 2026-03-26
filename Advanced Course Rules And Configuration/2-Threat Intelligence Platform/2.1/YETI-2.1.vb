# Yeti Platform - Deployment & AbuseIPDB Integration

This guide provides a step-by-step walkthrough for deploying the Yeti threat intelligence platform using Docker and manually configuring the AbuseIPDB analytics plugin.

---

## 🚀 1. Installation from GitHub

Clone the official repository and navigate to the production environment directory:


git clone https://github.com/yeti-platform/yeti-docker
cd yeti-docker/prod

🔑 2. Security Configuration
Generate a unique 32-byte hex token to secure your authentication:
openssl rand -hex 32


Open your .env file and add the generated token:
YETI_AUTH_SECRET_KEY=7f3a8b2c1d4e5f6a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2


🐳 3. Deployment
Start the Yeti stack in detached mode:

docker compose up -d


Web UI Access: Once the containers are healthy, the interface is available at http://0.0.0.0:80

Create Admin User
Generate your administrative credentials to log into the dashboard:
docker compose run --rm api create-user admin myStrongPass --admin


🛠️ 4. AbuseIPDB API Key Integration
To enable AbuseIPDB lookups, you must manually inject your API key into the task container.

Step A: Access the Container
docker exec -it yeti-task bash

Step B: Environment Setup

Inside the container, update the package list and install a text editor:
apt-get update && apt install nano -y
Step C: Modify the Plugin
Navigate to the analytics directory and edit the abuseipdb file:
cd /app/plugins/analytics/public/
nano abuseipdb
Locate the run function and update the api_key variable:

def run(self):
    # REPLACE THE OLD LINE WITH YOUR API KEY:
    api_key = "PASTE_YOUR_LONG_API_KEY_HERE"
Step D: Apply Changes
Exit the container and restart the task service to load the new configuration:


exit
docker restart yeti-tasks