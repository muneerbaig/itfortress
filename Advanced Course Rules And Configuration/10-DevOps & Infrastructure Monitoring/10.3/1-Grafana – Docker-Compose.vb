Grafana – Visualisation & Dashboarding

Create a project directory

mkdir -p /docker/grafana
cd /docker/grafana


Create docker-compose.yml

nano docker-compose.yml

version: "3.7"

services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"


Start Grafana

docker compose up -d
docker ps


