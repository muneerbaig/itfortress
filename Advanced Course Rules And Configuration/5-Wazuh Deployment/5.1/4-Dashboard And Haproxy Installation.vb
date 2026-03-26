Wazuh dashboard installation

Follow these steps to install the Wazuh dashboard.
Installing package dependencies

    Install the following packages if missing.

    apt-get install debhelper tar curl libcap2-bin #debhelper version 9 or later

Adding the Wazuh repository

Note

If you are installing the Wazuh dashboard on the same host as the Wazuh indexer or the Wazuh server, you may skip these steps as you may have added the Wazuh repository already.

    Install the following packages if missing.

        apt-get install gnupg apt-transport-https

    Install the GPG key.

        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

    Add the repository.

        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

    Update the packages information.

        apt-get update

Installing the Wazuh dashboard

    Install the Wazuh dashboard package.

    apt-get -y install wazuh-dashboard

Configuring the Wazuh dashboard

        Edit the /etc/wazuh-dashboard/opensearch_dashboards.yml file and replace the following values:

            server.host: This setting specifies the host of the Wazuh dashboard server. To allow remote users to connect, set the value to the IP address or DNS name of the Wazuh dashboard server. The value 0.0.0.0 will accept all the available IP addresses of the host.

            opensearch.hosts: The URLs of the Wazuh indexer instances to use for all your queries. The Wazuh dashboard can be configured to connect to multiple Wazuh indexer nodes in the same cluster. The addresses of the nodes can be separated by commas. For example, ["https://10.0.0.2:9200", "https://10.0.0.3:9200","https://10.0.0.4:9200"]


nano /etc/wazuh-dashboard/opensearch_dashboards.yml

server.port: 443
opensearch.hosts: ["https://192.168.15.140:9200", "https://192.168.15.141:9200","https://192.168.15.142:9200","https://192.168.15.143:9200"]
opensearch.ssl.verificationMode: certificate
#opensearch.username:
#opensearch.password:
opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"
server.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home



Deploying certificates


NODE_NAME=haproxy

mkdir /etc/wazuh-dashboard/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
 mv -n /etc/wazuh-dashboard/certs/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
 mv -n /etc/wazuh-dashboard/certs/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

systemctl daemon-reload
systemctl enable --now wazuh-dashboard
systemctl status wazuh-dashboard

 vim /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml

hosts:
   - default:
      url: https://192.168.15.140
      port: 55000
      username: wazuh-wui
      password: wazuh-wui
      run_as: false





Installtion Of the haproxy


Install the haproxy

apt install haproxy 


systemctl enable haproxy
mv /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bk
vim /etc/haproxy/haproxy.cfg

Configuration File (haproxy.cfg)

Paste the following configuration to handle TCP balancing for ports 1514 and 1515:

global
  chroot /var/lib/haproxy
  user haproxy
  group haproxy
  maxconn 4000
  pidfile /var/run/haproxy.pid
  stats socket /var/lib/haproxy/stats level admin
  log 127.0.0.1 local2 info

defaults
  mode http
  maxconn 4000
  log global
  option tcplog
  timeout connect 10s
  timeout client 1m
  timeout server 1m

frontend wazuh_register
  bind :1515
  mode tcp
  default_backend wazuh_register

frontend wazuh_reporting
  bind :1514
  mode tcp
  default_backend wazuh_reporting

backend wazuh_register
  mode tcp
  balance leastconn
  server master 192.168.15.140:1515 check
  server worker1 192.168.15.141:1515 check
  server worker2 192.168.15.142:1515 check
  server worker3 192.168.15.143:1515 check

backend wazuh_reporting
  mode tcp
  balance leastconn
  server master 192.168.15.140:1514 check
  server worker1 192.168.15.141:1514 check
  server worker2 192.168.15.142:1514 check
  server worker3 192.168.15.143:1514 check



  2. SSL Setup & Data Plane API

The Data Plane API allows the Wazuh Master to communicate with HAProxy over HTTPS.
Generate Certificates


openssl req -x509 -newkey rsa:4096 -keyout lb-key.pem -out lb-cert.pem -sha256 -nodes -addext "subjectAltName=IP:192.168.15.150" -subj "/C=BR/ST=SaoPaulo/O=Wazuh/CN=LoadBalancer-Internal"
mkdir -p /etc/haproxy/ssl/
mv lb-cert.pem lb-key.pem /etc/haproxy/ssl/


Install Data Plane API

curl -sL https://github.com/haproxytech/dataplaneapi/releases/download/v2.8.13/dataplaneapi_2.8.13_linux_x86_64.tar.gz | tar xz
cp dataplaneapi /usr/local/bin/


Configure dataplaneapi.yml

vim /etc/haproxy/dataplaneapi.yml


dataplaneapi:
  host: 0.0.0.0
  port: 5555
  tls:
    tls_port: 6443
    tls_certificate: /etc/haproxy/ssl/lb-cert.pem
    tls_key: /etc/haproxy/ssl/lb-key.pem
  user:
  - name: admin
    password: admin
    insecure: true
haproxy:
  config_file: /etc/haproxy/haproxy.cfg
  haproxy_bin: /usr/sbin/haproxy


⚙️ 3. Systemd Service for API

Create a service to ensure the API runs in the background.

vim /etc/systemd/system/dataplaneapi.service

[Unit]
Description=HAProxy Data Plane API
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dataplaneapi -f /etc/haproxy/dataplaneapi.yml
Restart=always

[Install]
WantedBy=multi-user.target


systemctl daemon-reload
systemctl enable --now dataplaneapi


🔗 4. Wazuh Manager Integration

On the Wazuh Master Node (192.168.15.140), configure the helper to talk to the Load Balancer.
Certificates on Manager

Generate a Manager certificate and copy the LB certificate:

openssl req -x509 -newkey rsa:4096 -keyout /etc/haproxy/cert/master-key.pem -out /etc/haproxy/cert/master-cert.pem -sha256 -nodes -addext "subjectAltName=IP:192.168.15.140" -subj "/C=BR/ST=SaoPaulo/O=Wazuh/CN=Manager-Internal"
# Ensure the lb-cert.pem is copied here as /etc/haproxy/cert/lb-cert.pem

Edit ossec.conf

Add the haproxy_helper block inside the <cluster> section:

<cluster>
  <haproxy_helper>
    <haproxy_disabled>no</haproxy_disabled>
    <haproxy_address>192.168.15.150</haproxy_address>
    <haproxy_user>admin</haproxy_user>
    <haproxy_password>admin</haproxy_password>
    <haproxy_protocol>https</haproxy_protocol>
    <haproxy_port>6443</haproxy_port>
    <haproxy_cert>/etc/haproxy/cert/lb-cert.pem</haproxy_cert>
    <client_cert_key>/etc/haproxy/cert/master-cert.pem</client_cert_key>
  </haproxy_helper>
</cluster>

Restart & Verify
Bash

/var/ossec/bin/wazuh-control restart
tail -f /var/ossec/logs/cluster.log | grep 'HAPHelper'

