Paste the code below after the <global></global> section:

 <integration>
     <name>custom-discord</name>
     <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXX</hook_url>
     <alert_format>json</alert_format>
 </integration>


 If files appear white, they lack execution permissions. Apply the correct ones:

 sudo chmod 750 /var/ossec/integrations/custom-*
sudo chown root:wazuh /var/ossec/integrations/custom-*

Restart Wazuh 

systemctl restart wazuh-manager