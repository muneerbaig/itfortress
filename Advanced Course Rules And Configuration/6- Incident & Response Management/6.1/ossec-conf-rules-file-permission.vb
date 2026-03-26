Where:

- `alert_source_link` in the script is set to the value of the Wazuh dashboard IP address. Replace `<IP ADDRESS>` with the Wazuh dashboard IP address.
- `alert_customer_id` is set as the value of the ID of the customer as it appears on the DFIR-IRIS dashboard. In this case, we
have configured the script to forward the alerts to customer ID `1`.(3) I have Set Customer Id:3


Set the ownership and permissions of the /var/ossec/integrations/custom-wazuh_iris.py file so that the root user and the wazuh group have access to it:

chmod 750 /var/ossec/integrations/custom-wazuh_iris.py
chown root:wazuh /var/ossec/integrations/custom-wazuh_iris.py

 Append the following configuration to the /var/ossec/etc/ossec.conf file to forward all alerts with a severity of 7 or higher to DFIR-IRIS:

 nano /var/ossec/etc/ossec.conf

 <ossec_config>

  <!-- IRIS integration -->
  <integration>
    <name>custom-wazuh_iris.py</name>
    <hook_url>https://<IRIS_IP_ADDRESS>/alerts/add</hook_url>
    <level>7</level>
    <api_key><IRIS_API_KEY></api_key> <!-- Replace with your IRIS API key -->
    <alert_format>json</alert_format>
  </integration>

</ossec_config>


