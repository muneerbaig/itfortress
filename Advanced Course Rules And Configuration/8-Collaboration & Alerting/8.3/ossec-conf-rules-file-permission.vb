Next lets change owner and also file permissions of custom-telegram

chmod 750 custom-telegram*
chown -R root:wazuh custom-telegram*


nano /var/ossec/etc/ossec.conf

<integration>
<name>custom-telegram</name> <hook_url>https://api.telegram.org/bot<API_KEY>/sendMessage</hook_url>
<alert_format>json</alert_format>
</integration>


