Set the ownership and permissions of the /var/ossec/integrations/custom-criminalip.py file so that the root user and the wazuh group have access to it:

chmod 750 /var/ossec/integrations/custom-criminalip.py
chown root:wazuh /var/ossec/integrations/custom-criminalip.py

Append the following configuration to the /var/ossec/etc/ossec.conf file to enable Wazuh to query the Criminal IP API and enrich alerts for the specified groups. Replace <CRIMINALIP_API_KEY> with your own Criminal IP API key:

<ossec_config>
  <integration>
    <name>custom-criminalip.py</name>
    <api_key><CRIMINALIP_API_KEY></api_key> <!-- Replace with your Criminal IP API key -->
    <group>web, sshd, invalid_login, firewall, ids, system, database, application</group>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>

Create a file /var/ossec/etc/rules/criminal_ip_ruleset.xml with the following rules:

<group name="criminalip,">


  <!-- Main Criminal IP Rule -->

  <rule id="100623" level="2">
    <decoded_as>json</decoded_as>
    <field name="integration">criminalip</field>
    <description>Criminal IP Events</description>
  </rule>


  <!-- VPN Detection Rule -->

  <rule id="100624" level="6">
    <if_sid>100623</if_sid>
    <field name="criminalip.is_vpn">true</field>
    <description>IP address associated with a VPN service detected: $(criminalip.ip)</description>
  </rule>


  <!-- TOR Detection Rule -->

  <rule id="100625" level="10">
    <if_sid>100623</if_sid>
    <field name="criminalip.is_tor">true</field>
    <description>IP address associated with TOR network detected: $(criminalip.ip)</description>
  </rule>


  <!-- Proxy Detection Rule -->

  <rule id="100626" level="5">
    <if_sid>100623</if_sid>
    <field name="criminalip.is_proxy">true</field>
    <description>IP address associated with a Proxy server detected: $(criminalip.ip)</description>
  </rule>


  <!-- Dark Web Activity Rule -->

  <rule id="100627" level="8">
    <if_sid>100623</if_sid>
    <field name="criminalip.is_darkweb">true</field>
    <description>IP address associated with Dark web activity detected: $(criminalip.ip)</description>
  </rule>


  <!-- Critical Score Rule -->

  <rule id="100628" level="8">
    <if_sid>100623</if_sid>
    <field name="criminalip.score_inbound">Critical</field>
    <description>Critical risk score for IP address: $(criminalip.ip)</description>
  </rule>


  <!-- Dangerous Score Rule -->

  <rule id="100629" level="9">
    <if_sid>100623</if_sid>
    <field name="criminalip.score_inbound">Dangerous</field>
    <description>Dangerous risk score for IP address: $(criminalip.ip)</description>
  </rule>


  <!-- Moderate Score Rule -->

  <rule id="100630" level="6">
    <if_sid>100623</if_sid>
    <field name="criminalip.score_inbound">Moderate</field>
    <description>Moderate risk score for IP address: $(criminalip.ip)</description>
  </rule>


  <!-- Low Score Rule -->

  <rule id="100631" level="3">
    <if_sid>100623</if_sid>
    <field name="criminalip.score_inbound">Low</field>
    <description>Low risk score for IP address: $(criminalip.ip)</description>
  </rule>



  <!-- Hosting Detection Rule -->

  <rule id="100633" level="5">
    <if_sid>100623</if_sid>
    <field name="criminalip.is_hosting">true</field>
    <description>IP address associated with a Hosting service detected: $(criminalip.ip)</description>
  </rule>


  <!-- Cloud Service Detection Rule -->

  <rule id="100634" level="4">
    <if_sid>100623</if_sid>
    <field name="criminalip.is_cloud">true</field>
    <description>IP address associated with Cloud service detected : $(criminalip.ip)</description>
  </rule>


  <!-- Scanner Activity Detection Rule -->

  <rule id="100636" level="7">
    <if_sid>100623</if_sid>
    <field name="criminalip.is_scanner">true</field>
    <description>IP address associated with scanner activity detected: $(criminalip.ip)</description>
  </rule>

<!-- Mobile Network Detection Rule, This rule may cause high false positives and can be uncommented based on user preference 

  <rule id="100637" level="4">
    <if_sid>100623</if_sid>
    <field name="criminalip.is_mobile">true</field>
    <description>IP address associated with a Mobile network detected: $(criminalip.ip)</description>
  </rule>

 -->

  <!-- Anonymous VPN Detection Rule -->

  <rule id="100638" level="5">
    <if_sid>100623</if_sid>
    <field name="criminalip.is_anonymous_vpn">true</field>
    <description>IP address associated with an Anonymous VPN detected: $(criminalip.ip)</description>
  </rule>


  <!-- Error: Missing Parameter -->

  <rule id="100640" level="5">
    <if_sid>100623</if_sid>
    <field name="full_log">.*Missing Parameter.*</field>
    <description>CriminalIP API error: Missing parameter in request</description>
  </rule>


  <!-- Error: Invalid IP Address -->

  <rule id="100641" level="5">
    <if_sid>100623</if_sid>
    <field name="full_log">.*Invalid IP Address.*</field>
    <description>CriminalIP API error: Invalid IP address format</description>
  </rule>


  <!-- Error: Internal Server Error -->

  <rule id="100642" level="7">
    <if_sid>100623</if_sid>
    <field name="full_log">.*Internal Server Error.*</field>
    <description>CriminalIP API error: Internal server error encountered</description>
  </rule>


</group>


Set the ownership and permissions of the /var/ossec/etc/rules/criminal_ip_ruleset.xml  file:

chmod 660 /var/ossec/etc/rules/criminal_ip_ruleset.xml 
chown wazuh:wazuh /var/ossec/etc/rules/criminal_ip_ruleset.xml

Restart the Wazuh manager to apply the changes:

systemctl restart wazuh-manager

 Install Tor and proxychains:

 apt update
apt install tor proxychains4

Edit the proxychains configuration file /etc/proxychains4.conf, and add or uncomment the Tor proxy socks4 127.0.0.1 9050.

socks4 127.0.0.1 9050

Start the Tor service and ensure Tor is running:

systemctl start tor
systemctl status tor


# Ubuntu endpoint

Perform the following steps to install an Apache web server and monitor its logs with the Wazuh agent.

1. Update local packages and install the Apache web server:

apt update
apt install apache2

2. If the firewall is enabled, modify the firewall to allow external access to web ports. Skip this step if the firewall is disabled:


ufw status
ufw app list
ufw allow 'Apache'

Check the status of the Apache service to verify that the web server is running:Check the status of the Apache service to verify that the web server is running:
systemctl status apache2

 Use the curl command or open http://<UBUNTU_IP> in a browser to view the Apache landing page and verify the installation:

    curl http://<UBUNTU_IP>

Append the following configuration to the /var/ossec/etc/ossec.conf file to monitor the Apache access logs:

<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
</ossec_config>

Restart the Wazuh agent to apply the changes:

systemctl restart wazuh-agent

1. Simulating Tor activity

Follow the steps below to test the integration by simulating an attack and generating an alert of an IP address associated with Tor network usage. In this scenario, we will simulate directory traversal using a known Tor IP address on the web server.

Perform the following steps on the Kali Linux endpoint.

1. Install Tor and proxychains:

apt update
apt install tor proxychains4

Edit the proxychains configuration file /etc/proxychains4.conf, and add or uncomment the Tor proxy socks4 127.0.0.1 9050.

socks4 127.0.0.1 9050

Start the Tor service and ensure Tor is running:

systemctl start tor
systemctl status tor

Access the web server using the corresponding Ubuntu endpoint IP address. Replace <UBUNTU_IP> with the IP address of the Ubuntu endpoint.

    curl "http://10.10.20.51/index.html?param=../../../../etc/passwd"


## Testing : **WAZUH - Criminal IP**

**1) TOR**

echo "185.220.101.1 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /index.html?file=../../../../etc/passwd HTTP/1.1\" 400 532 \"-\" \"curl/7.88.1\"" | sudo tee -a /var/log/apache2/access.log

2) DigitalOcean / Hosting 

echo "104.248.199.66 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /phpmyadmin/ HTTP/1.1\" 400 210 \"-\" \"Mozilla/5.0\"" | sudo tee -a /var/log/apache2/access.log


3) DigitalOcean / Hosting

echo "157.245.72.224 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /wp-login.php HTTP/1.1\" 400 210 \"-\" \"Mozilla/5.0\"" | sudo tee -a /var/log/apache2/access.log

4) Microsoft Azure / Cloud

echo "104.210.140.140 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /admin HTTP/1.1\" 400 210 \"-\" \"Mozilla/5.0\"" | sudo tee -a /var/log/apache2/access.log


5)Take From Criminal Websites:

echo "193.32.162.82 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /?q=%27%20or%201=1-- HTTP/1.1\" 400 210 \"-\" \"sqlmap/1.7\"" | sudo tee -a /var/log/apache2/access.log


6) Hong Kong

echo "152.32.135.217 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /index.php?file=../../../../etc/shadow HTTP/1.1\" 400 532 \"-\" \"curl/7.88.1\"" | sudo tee -a /var/log/apache2/access.log