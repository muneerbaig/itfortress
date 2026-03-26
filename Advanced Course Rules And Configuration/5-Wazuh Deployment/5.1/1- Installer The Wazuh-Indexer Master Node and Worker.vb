Wazuh Indexer Multi-Node Cluster Installation v4


Installer The Wazuh-Indexer Master Node and Worker:

Generating the SSL certificates

    Download the wazuh-certs-tool.sh script and the config.yml configuration file. This creates the certificates that encrypt communications between the Wazuh central components.

    curl -sO https://packages.wazuh.com/4.14/wazuh-certs-tool.sh
    curl -sO https://packages.wazuh.com/4.14/config.yml


Edit ./config.yml and replace the node names and IP values with the corresponding names and IP addresses. You need to do this for all Wazuh server, Wazuh indexer, and Wazuh dashboard nodes. Add as many node fields as needed.

nodes:
  # Wazuh indexer nodes
  indexer:
    - name: master
      ip: "192.168.15.140"
    - name: worker1
      ip: "192.168.15.141"
    - name: worker2
      ip: "192.168.15.142"
    - name: worker3
      ip: "192.168.15.143"

  # Wazuh server nodes
  # If there is more than one Wazuh server
  # node, each one must have a node_type
  server:
    - name: master
      ip: "192.168.15.140"
      node_type: master
    - name: worker1
      ip: "192.168.15.141"
      node_type: worker
    - name: worker2
      ip: "192.168.15.142"
      node_type: worker
    - name: worker3
      ip: "192.168.15.143"
      node_type: worker
      
  # Wazuh dashboard nodes
  dashboard:
    - name: haproxy
      ip: "192.168.15.150"    



Run ./wazuh-certs-tool.sh to create the certificates. For a multi-node cluster, these certificates need to be later deployed to all Wazuh instances in your cluster.

bash ./wazuh-certs-tool.sh -A

Compress all the necessary files.

tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
rm -rf ./wazuh-certificates

Forward To all node (Worke1 worker2 worker3 haproxy-dashboard)

Copy the wazuh-certificates.tar file to all the nodes, including the Wazuh indexer, Wazuh server, and Wazuh dashboard nodes. This can be done by using the scp utility.

apt install openssh-client

scp wazuh-certificates.tar root@192.168.15.141:/root

scp wazuh-certificates.tar root@192.168.15.142:/root

scp wazuh-certificates.tar root@192.168.15.143:/root

scp wazuh-certificates.tar root@192.168.15.150:/root


Installing package dependencies

    Run the following command to install the following packages if missing:

    apt-get install debconf adduser procps

    Adding the Wazuh repository

    apt-get install gnupg apt-transport-https
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    apt-get update


Installing the Wazuh indexer

    Install the Wazuh indexer package.
    apt-get -y install wazuh-indexer


Configuring the Wazuh indexer

    Edit /etc/wazuh-indexer/opensearch.yml and replace the following values:

        network.host: Sets the address of this node for both HTTP and transport traffic. The node will bind to this address and use it as its publish address. Accepts an IP address or a hostname.

        Use the same node address set in config.yml to create the SSL certificates.

        node.name: Name of the Wazuh indexer node as defined in the config.yml file. For example, node-1.

        cluster.initial_master_nodes: List of the names of the master-eligible nodes. These names are defined in the config.yml file. Uncomment the node-2 and node-3 lines, change the names, or add more lines, according to your config.yml definitions.

   nano /etc/wazuh-indexer/opensearch.yml 

   network.host: "192.168.15.140"
node.name: "master"
cluster.initial_master_nodes:
- "master"
- "worker1"
- "worker2"
- "worker3"
cluster.name: "wazuh-cluster"
discovery.seed_hosts:
  - "192.168.15.140"
  - "192.168.15.141"
  - "192.168.15.142"
  - "192.168.15.143"    
node.max_local_storage_nodes: "4"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.authcz.admin_dn:
- "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
- "CN=master,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker1,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker2,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker3,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"

plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]

### Option to allow Filebeat-oss 7.10.2 to work ###
compatibility.override_main_response_version: true


Run the following commands, replacing <INDEXER_NODE_NAME> with the name of the Wazuh indexer node you are configuring as defined in config.yml. For example, node-1. This deploys the SSL certificates to encrypt communications between the Wazuh central components.

NODE_NAME=master
mkdir /etc/wazuh-indexer/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

systemctl daemon-reload
systemctl enable --now wazuh-indexer
systemctl status wazuh-indexer


        


Worke1

Wazuh indexer nodes installation

Follow these steps to install and configure a single-node or multi-node Wazuh indexer.
Installing package dependencies

    Run the following command to install the following packages if missing:

    apt-get install debconf adduser procps
    Adding the Wazuh repository
    apt-get install gnupg apt-transport-https
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    apt-get update


Installing the Wazuh indexer

    Install the Wazuh indexer package.
    apt-get -y install wazuh-indexer

Configuring the Wazuh indexer

    Edit /etc/wazuh-indexer/opensearch.yml and replace the following values:

        network.host: Sets the address of this node for both HTTP and transport traffic. The node will bind to this address and use it as its publish address. Accepts an IP address or a hostname.

        Use the same node address set in config.yml to create the SSL certificates.

        node.name: Name of the Wazuh indexer node as defined in the config.yml file. For example, node-1.

        cluster.initial_master_nodes: List of the names of the master-eligible nodes. These names are defined in the config.yml file. Uncomment the node-2 and node-3 lines, change the names, or add more lines, according to your config.yml definitions.


nano /etc/wazuh-indexer/opensearch.yml

network.host: "192.168.15.141"
node.name: "worker1"
cluster.initial_master_nodes:
- "master"
- "worker1"
- "worker2"
- "worker3"
cluster.name: "wazuh-cluster"
discovery.seed_hosts:
  - "192.168.15.140"
  - "192.168.15.141"
  - "192.168.15.142"
  - "192.168.15.143"    
node.max_local_storage_nodes: "4"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.authcz.admin_dn:
- "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
- "CN=master,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker1,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker2,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker3,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"

plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]

### Option to allow Filebeat-oss 7.10.2 to work ###
compatibility.override_main_response_version: true

 NODE_NAME=worker1

 mkdir /etc/wazuh-indexer/certs
 tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
 mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
 mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
 chmod 500 /etc/wazuh-indexer/certs
 chmod 400 /etc/wazuh-indexer/certs/*
 chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

 systemctl daemon-reload
 systemctl enable --now wazuh-indexer
 systemctl status wazuh-indexer





worker2

Wazuh indexer nodes installation

Follow these steps to install and configure a single-node or multi-node Wazuh indexer.
Installing package dependencies

    Run the following command to install the following packages if missing:

    apt-get install debconf adduser procps

Adding the Wazuh repository

    Install the following packages if missing.

        apt-get install gnupg apt-transport-https

    Install the GPG key.

        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

    Add the repository.

        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

    Update the packages information.

        apt-get update

Installing the Wazuh indexer

    Install the Wazuh indexer package.

    apt-get -y install wazuh-indexer

Configuring the Wazuh indexer

    Edit /etc/wazuh-indexer/opensearch.yml and replace the following values:

        network.host: Sets the address of this node for both HTTP and transport traffic. The node will bind to this address and use it as its publish address. Accepts an IP address or a hostname.

        Use the same node address set in config.yml to create the SSL certificates.

        node.name: Name of the Wazuh indexer node as defined in the config.yml file. For example, node-1.

        cluster.initial_master_nodes: List of the names of the master-eligible nodes. These names are defined in the config.yml file. Uncomment the node-2 and node-3 lines, change the names, or add more lines, according to your config.yml definitions.


nano /etc/wazuh-indexer/opensearch.yml

network.host: "192.168.15.142"
node.name: "worker2"
cluster.initial_master_nodes:
- "master"
- "worker1"
- "worker2"
- "worker3"
cluster.name: "wazuh-cluster"
discovery.seed_hosts:
  - "192.168.15.140"
  - "192.168.15.141"
  - "192.168.15.142"
  - "192.168.15.143"    
node.max_local_storage_nodes: "4"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.authcz.admin_dn:
- "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
- "CN=master,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker1,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker2,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker3,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"

plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]

### Option to allow Filebeat-oss 7.10.2 to work ###
compatibility.override_main_response_version: true

 NODE_NAME=worker2

 mkdir /etc/wazuh-indexer/certs
 tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
 mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
 mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
 chmod 500 /etc/wazuh-indexer/certs
 chmod 400 /etc/wazuh-indexer/certs/*
 chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

 systemctl daemon-reload
 systemctl enable --now wazuh-indexer
 systemctl status wazuh-indexer




 
worker3

Wazuh indexer nodes installation

Follow these steps to install and configure a single-node or multi-node Wazuh indexer.
Installing package dependencies

    Run the following command to install the following packages if missing:

    apt-get install debconf adduser procps

Adding the Wazuh repository

    Install the following packages if missing.

        apt-get install gnupg apt-transport-https

    Install the GPG key.

        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

    Add the repository.

        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

    Update the packages information.

        apt-get update

Installing the Wazuh indexer

    Install the Wazuh indexer package.

    apt-get -y install wazuh-indexer

Configuring the Wazuh indexer

    Edit /etc/wazuh-indexer/opensearch.yml and replace the following values:

        network.host: Sets the address of this node for both HTTP and transport traffic. The node will bind to this address and use it as its publish address. Accepts an IP address or a hostname.

        Use the same node address set in config.yml to create the SSL certificates.

        node.name: Name of the Wazuh indexer node as defined in the config.yml file. For example, node-1.

        cluster.initial_master_nodes: List of the names of the master-eligible nodes. These names are defined in the config.yml file. Uncomment the node-2 and node-3 lines, change the names, or add more lines, according to your config.yml definitions.


nano /etc/wazuh-indexer/opensearch.yml

network.host: "192.168.15.143"
node.name: "worker3"
cluster.initial_master_nodes:
- "master"
- "worker1"
- "worker2"
- "worker3"
cluster.name: "wazuh-cluster"
discovery.seed_hosts:
  - "192.168.15.140"
  - "192.168.15.141"
  - "192.168.15.142"
  - "192.168.15.143"    
node.max_local_storage_nodes: "4"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.authcz.admin_dn:
- "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
- "CN=master,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker1,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker2,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=worker3,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"

plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]

### Option to allow Filebeat-oss 7.10.2 to work ###
compatibility.override_main_response_version: true

NODE_NAME=worker3

 mkdir /etc/wazuh-indexer/certs
 tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
 mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
 mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
 chmod 500 /etc/wazuh-indexer/certs
 chmod 400 /etc/wazuh-indexer/certs/*
 chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

 systemctl daemon-reload
 systemctl enable --now wazuh-indexer
 systemctl status wazuh-indexer

 /usr/share/wazuh-indexer/bin/indexer-security-init.sh         ---master and worker-all nnode

 curl -k -u admin:admin https://192.168.15.140:9200/_cat/nodes?v  ---master and worker-all node

 curl -k -u admin:admin https://192.168.15.140:9200      --master and worker -all node

