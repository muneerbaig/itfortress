We change the files’ permission and the ownership to ensure that Wazuh has adequate permissions to access and run them:

The correct ownership for Wazuh 4is `root:wazuh`

sudo chmod 755 /var/ossec/integrations/custom-w2thive.py
sudo chmod 755 /var/ossec/integrations/custom-w2thive
sudo chown root:ossec /var/ossec/integrations/custom-w2thive.py
sudo chown root:ossec /var/ossec/integrations/custom-w2thive

To allow Wazuh to run the integration script, we add the following lines to the manager configuration file located at /var/ossec/etc/ossec.conf. We insert the IP address for TheHive server along with the API key that was generated earlier:

<ossec_config>
…
  <integration>
    <name>custom-w2thive</name>
    <hook_url>http://TheHive_Server_IP:9000</hook_url>
    <api_key>RWw/Ii0yE6l+Nnd3nv3o3Uz+5UuHQYTM</api_key>
    <alert_format>json</alert_format>
  </integration>
…
</ossec_config>

Restart the manager to apply the changes:

sudo systemctl restart wazuh-manager

