1. **In the Wazuh realm, navigate to Clients > Settings and ensure the Enabled switch is turned on. Then configure the following parameters** 
- **Client ID**: wazuh-saml
- **Name**: Wazuh SSO
- **Valid Redirect URIs**: [https://10.117.33.145/*](https://10.0.2.4/*) (Replace 10.0.2.4 with your own Wazuh dashboard IP)
- **IDP-Initiated SSO URL Name**: wazuh-dashboard
- **Name ID Format**: username
- **Force POST Binding**: ON
- **Include AuthnStatement**: ON
- **Sign Documents**: ON
- **Sign Assertions**: ON
- **Signature Algorithm**: RSA_SHA256
- **SAML Signature Key Name**: KEY_ID
- **Canonicalization Method**: EXCLUSIVE
- **Front Channel Logout**: ON

2. **Next, go to Clients > Advanced > Fine Grain SAML Endpoint Configuration and complete the section with these parameters:**

Assertion Consumer Service POST Binding URL: `https://10.10.40.10/_opendistro/_security/saml/acs/idpinitiated`

Logout Service Redirect Binding URL: [https://10.](https://10.0.2.4/)117.33.145

Leave the rest of the values as default. **Save** to apply the configuration

3. **Next, edit the /etc/wazuh-indexer/opensearch-security/config.yml file and update the following settings:**
- In basic_internal_auth_domain, set **order** to 0.
- Set the **challenge** flag to false
- openssl rand -hex 32


      saml_auth_domain:
        http_enabled: true
        transport_enabled: false
        order: 1
        http_authenticator:
          type: saml
          challenge: true
          config:
            idp:
              metadata_file: '/etc/wazuh-indexer/opensearch-security/idp-metadata.xml'
              entity_id: 'http://192.168.31.95:8080/realms/Wazuh'
            sp:
              entity_id: wazuh-saml
              metadata_file: '/etc/wazuh-indexer/opensearch-security/sp-metadata.xml'
            kibana_url: https://192.168.31.95
            roles_key: Roles
            exchange_key: '0fdd1f511aeb919d62b69c51a41b3b6d66c4069566cce2ad3de36ad3d1b0920b'
        authentication_backend:
          type: noop



4. **Ensure the correct values are entered for the following parameters in** /etc/wazuh-indexer/opensearch-security/config.yml:
- idp.metadata_file
- idp.entity_id
- sp.entity_id
- sp.metadata_file
- kibana_url
- roles_key
- exchange_key



Then, run the securityadmin script as root to apply the configuration changes

export JAVA_HOME=/usr/share/wazuh-indexer/jdk/ && bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /etc/wazuh-indexer/opensearch-security/config.yml -icl -key /etc/wazuh-indexer/certs/admin-key.pem -cert /etc/wazuh-indexer/certs/admin.pem -cacert /etc/wazuh-indexer/certs/root-ca.pem -h 127.0.0.1 -nhnv


Next, configure the /etc/wazuh-indexer/opensearch-security/roles_mapping.yml file to map the Keycloak realm role to the appropriate Wazuh indexer role. In this case, map it to the all_access role:

sudo nano /etc/wazuh-indexer/opensearch-security/roles_mapping.yml

reserved:false
backend_roles:
admin --what ever name create in Realm Keycloak it should be matching name (In case wrong name wazuh dashboard permission deined:)

Save the changes and run the securityadmin script as root again to load the configuration changes made in the roles_mapping.yml file

export JAVA_HOME=/usr/share/wazuh-indexer/jdk/ && bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /etc/wazuh-indexer/opensearch-security/roles_mapping.yml -icl -key /etc/wazuh-indexer/certs/admin-key.pem -cert /etc/wazuh-indexer/certs/admin.pem -cacert /etc/wazuh-indexer/certs/root-ca.pem -h 127.0.0.1 -nhnv

**Wazuh dashboard configuration**

Open the wazuh.yml file at /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml configuration file. Change the ‘url’ from **127.0.0.1** to the url of the wazuh dashboard  Additionally, If **run_as** is set to false, proceed to the next step.

Edit the Wazuh dashboard configuration file by adding these configurations to the /etc/wazuh-dashboard/opensearch_dashboards.yml file

nano  /etc/wazuh-dashboard/opensearch_dashboards.yml 

opensearch_security.auth.type: "saml"
server.xsrf.allowlist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout", "/_opendistro/_security/saml/acs/idpinitiated"]
opensearch_security.session.keepalive: false

systemctl restart wazuh-dashboard

