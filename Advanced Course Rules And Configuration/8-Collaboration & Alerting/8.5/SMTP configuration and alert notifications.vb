Email – SMTP configuration and alert notifications

Run this command to install the required packages. Select No configuration, if prompted about the mail server configuration type.

apt-get update && apt-get install postfix mailutils libsasl2-2 ca-certificates libsasl2-modules

Append these lines to the /etc/postfix/main.cf file to configure Postfix. Create the file if missing.

relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_use_tls = yes
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination


Set the credentials of the sender in the /etc/postfix/sasl_passwd file and create a database file for Postfix. Replace the <USERNAME> and <PASSWORD> variables with sender's email address username and password respectively.

echo '[smtp.gmail.com]:587 @gmail.com:Apppassword' | sudo tee /etc/postfix/sasl_passwd > /dev/null
chown root:root /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
sudo chmod 0600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd
sudo systemctl restart postfix


Restart Postfix to effect the configuration changes:

systemctl restart postfix

Run the following command to test the configuration:

echo "Test mail from postfix" | mail -s "Test Postfix" -r "<CONFIGURED_EMAIL>" <RECEIVER_EMAIL>

Configure email notifications within the <global> tag of the Wazuh server's /var/ossec/etc/ossec.conf file as follows:

<global>
  <email_notification>yes</email_notification>
  <smtp_server>localhost</smtp_server>
  <email_from><USERNAME>@gmail.com</email_from>
  <email_to><RECEIVER_EMAIL></email_to>
</global>


Restart the Wazuh manager to apply the changes:

systemctl restart wazuh-manager

EMAIL WITH VIA DASHBOARD


First things Need to give the permission in path of the directories side: IF suppose we aint given permission config file wont be work:

chown root:wazuh-indexer /etc/default/wazuh-indexer
chmod 644 /etc/default/wazuh-indexer


echo "your-email@gmail.com" | sudo -u wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch-keystore add opensearch.notifications.core.email.gmail.username --

echo "your-app-password" | sudo -u wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch-keystore add opensearch.notifications.core.email.gmail.password --


Next Once done configuration: Restart Wazuh-Indexer:

Systemctl restart wazuh-indexer



REMOVE:

sudo -u wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch-keystore remove opensearch.notifications.core.email.gmail.username

sudo -u wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch-keystore remove opensearch.notifications.core.email.gmail.password

