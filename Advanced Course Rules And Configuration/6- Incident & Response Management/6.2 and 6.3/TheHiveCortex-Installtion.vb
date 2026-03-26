TheHive

Create the Directories  TheHive/Cortex

mkdir -p thehivecortex && cd thehivecortex 

And next create inside the thehivecortex 


nano docker-compose.yml

mkdir -p cortex

version: "3.7"

services:
  thehive:
    image: strangebee/thehive:5.2
    restart: unless-stopped
    depends_on:
      - cassandra
      - elasticsearch
      - minio
      - cortex
    mem_limit: 1500m
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms1024M -Xmx1024M
    command:
      - --secret
      - "lab123456789"
      - --cql-hostnames
      - cassandra
      - --index-backend
      - elasticsearch
      - --es-hostnames
      - elasticsearch
      - --s3-endpoint
      - http://minio:9002
      - --s3-access-key
      - minioadmin
      - --s3-secret-key
      - minioadmin
      - --s3-use-path-access-style
    volumes:
      - thehivedata:/etc/thehive/application.conf
    networks:
      - SOC_NET

  cassandra:
    image: cassandra:4
    restart: unless-stopped
    ports:
      - "9042:9042"
    environment:
      - CASSANDRA_CLUSTER_NAME=TheHive
    volumes:
      - cassandradata:/var/lib/cassandra
    networks:
      - SOC_NET

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    restart: unless-stopped
    mem_limit: 512m
    ports:
      - "9200:9200"
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - cluster.name=hive
      - http.host=0.0.0.0
      - ES_JAVA_OPTS=-Xms256m -Xmx256m
    volumes:
      - elasticsearchdata:/usr/share/elasticsearch/data
    networks:
      - SOC_NET

  minio:
    image: quay.io/minio/minio
    restart: unless-stopped
    command: ["minio", "server", "/data", "--console-address", ":9002"]
    environment:
      - MINIO_ROOT_USER=minioadmin
      - MINIO_ROOT_PASSWORD=minioadmin
    ports:
      - "9002:9002"
    volumes:
      - miniodata:/data
    networks:
      - SOC_NET

  cortex:
    image: thehiveproject/cortex:3.1.7
    container_name: cortex
    restart: unless-stopped
    depends_on:
      - elasticsearch
    volumes:
      - ./cortex/application.conf:/etc/cortex/application.conf
      - /var/run/docker.sock:/var/run/docker.sock
      - /tmp:/tmp
    environment:
      - http_proxy=${http_proxy}
      - https_proxy=${https_proxy}
    ports:
      - "9001:9001"
    networks:
      - SOC_NET

volumes:
  miniodata:
  cassandradata:
  elasticsearchdata:
  thehivedata:

networks:
  SOC_NET:
    driver: bridge


