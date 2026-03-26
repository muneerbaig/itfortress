Issued Of Auth Keys Cortex intergated Thehive

## Create the config directory on the host

On your host machine:

mkdir -p /home/threat/thehive/config

2️⃣ Create the configuration file

nano /home/threat/thehive/config/application.conf

Paste this configuration:

play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule

cortex {
  servers = [
    {
      name = "Cortex"
      url = "http://cortex:9001"
      auth {
        type = "bearer"
        key = "ye8yPYxi5Ba0lu1+6vBecRTe0l4SqHoe"
      }
    }
  ]
}


Fix your docker-compose.yml

Replace this incorrect line:

- thehivedata:/etc/thehive/application.conf
with:
- ./config/application.conf:/etc/thehive/application.conf

Your TheHive service should look like this:

thehive:
  image: strangebee/thehive:5.2
  restart: unless-stopped
  depends_on:
    - cassandra
    - elasticsearch
    - minio
    - cortex
  ports:
    - "9000:9000"
  volumes:
    - ./config/application.conf:/etc/thehive/application.conf
  networks:
    - SOC_NET


 Restart the stack

 Run:
 docker compose down
docker compose up -d