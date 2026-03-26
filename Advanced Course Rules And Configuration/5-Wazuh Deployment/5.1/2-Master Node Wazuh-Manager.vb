Installer do Wazuh manager

Master Node Wazuh-Manager:

Installing the Wazuh manager

    Install the Wazuh manager package.

    apt-get -y install wazuh-manager



Installing Filebeat

    Install the Filebeat package.

    apt-get -y install filebeat

Configuring Filebeat

    Download the preconfigured Filebeat configuration file.

    curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.14/tpl/wazuh/filebeat/filebeat.yml

    Edit the /etc/filebeat/filebeat.yml configuration file and replace the following value:

        hosts: The list of Wazuh indexer nodes to connect to. You can use either IP addresses or hostnames. By default, the host is set to localhost hosts: ["127.0.0.1:9200"]. Replace your Wazuh indexer IP address accordingly.

        If you have more than one Wazuh indexer node, you can separate the addresses using commas. For example, hosts: ["10.0.0.1:9200", "10.0.0.2:9200", "10.0.0.3:9200"]

nano /etc/filebeat/filebeat.yml

# Wazuh - Filebeat configuration file
output.elasticsearch:
  hosts: ["192.168.15.140:9200", "192.168.15.141:9200", "192.168.15.142:9200", "192.168.15.143:9200"]
  protocol: https


    Create a Filebeat keystore to securely store authentication credentials.

    filebeat keystore create

    Add the default username and password admin:admin to the secrets keystore.

    echo admin | filebeat keystore add username --stdin --force
    echo admin | filebeat keystore add password --stdin --force

    Download the alerts template for the Wazuh indexer.

    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.14.4/extensions/elasticsearch/7.x/wazuh-template.json
    chmod go+r /etc/filebeat/wazuh-template.json

    Install the Wazuh module for Filebeat.

    curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.5.tar.gz | tar -xvz -C /usr/share/filebeat/module

Deploying certificates

NODE_NAME=master

 mkdir /etc/filebeat/certs
 tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
 mv -n /etc/filebeat/certs/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
 mv -n /etc/filebeat/certs/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
 chmod 500 /etc/filebeat/certs
 chmod 400 /etc/filebeat/certs/*
 chown -R root:root /etc/filebeat/certs

 echo admin | /var/ossec/bin/wazuh-keystore -f indexer -k username
 echo admin | /var/ossec/bin/wazuh-keystore -f indexer -k password



Edit /var/ossec/etc/ossec.conf to configure the indexer connection.

By default, the indexer settings have one host configured. It's set to 0.0.0.0 as highlighted below.
nano /var/ossec/etc/ossec.conf
openssl rand -hex 16


<indexer>
  <enabled>yes</enabled>
  <hosts>
    <host>https://192.168.15.140:9200</host>
    <host>https://192.168.15.141:9200</host>
    <host>https://192.168.15.142:9200</host>
    <host>https://192.168.15.143:9200</host>
  </hosts>
  <ssl>


<cluster>
    <name>wazuh</name>
    <node_name>master</node_name>
    <key>b9367d8ae17992f9aefef845f0a79a8f</key>
    <node_type>master</node_type>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>192.168.15.140</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
</cluster>


systemctl daemon-reload
systemctl enable --now wazuh-manager
systemctl status wazuh-manager

 /var/ossec/bin/cluster_control -l

 systemctl restart filebeat

 filebeat test output

 /var/ossec/bin/wazuh-modulesd
