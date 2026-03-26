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

 

    