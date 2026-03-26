## Configure the Wazuh Manager

Go to `/var/ossec/etc/ossec.conf` in your terminal and include this in the `ossec.conf` file

nano /var/ossec/etc/ossec.conf

<ossec_config>
   <integration>
     <name>slack</name>
     <hook_url><SLACK_WEBHOOK_URL></hook_url> <! — Replace with your Slack hook URL →
     <alert_format>json</alert_format>
   </integration>
</ossec_config>

