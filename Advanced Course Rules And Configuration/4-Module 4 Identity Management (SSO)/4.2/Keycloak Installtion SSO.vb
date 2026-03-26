Create the new directories for Key cloak inside path create new file name (docker-compose.yml) add in command..Make sure that add your ip address in (KC_HOSTNAME):Once add the scripts save and exit.

nano docker-compose.yml


version: '3.8'

services:
  postgres:
    image: postgres:16.2
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - keycloak_network

  keycloak:
    image: quay.io/keycloak/keycloak:26.5.4
    command: start-dev
    environment:
      KC_HOSTNAME: 192.168.31.246
      KC_HOSTNAME_PORT: 8080
      KC_HOSTNAME_STRICT_BACKCHANNEL: 'false'
      KC_HTTP_ENABLED: 'true'
      KC_HOSTNAME_STRICT_HTTPS: 'false'
      KC_HEALTH_ENABLED: 'true'
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/${POSTGRES_DB}
      KC_DB_USERNAME: ${POSTGRES_USER}
      KC_DB_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "8080:8080"
    restart: always
    depends_on:
      - postgres
    networks:
      - keycloak_network

volumes:
  postgres_data:

networks:
  keycloak_network:
    driver: bridge



Next create the file for .env , add the strong password inside the scirpts:Once add the scripts save and exit (MAKE SURE ADD THE PASSWORD OF ADMIN AND POSTGRES-PASSWORD)

nano .env

# .env file
POSTGRES_DB=keycloak
POSTGRES_USER=keycloak
POSTGRES_PASSWORD=your_strong_postgres_password

KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=your_strong_admin_password


Now, launch Keycloak by running:

docker compose up -d

