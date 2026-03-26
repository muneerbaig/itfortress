sudo chmod 750 /var/ossec/integrations/custom-yeti.py
sudo chown root:wazuh /var/ossec/integrations/custom-yeti.py


Edit the Wazuh manager config:

sudo nano /var/ossec/etc/ossec.conf

Inside <ossec_config>, add:

<integration>
  <name>custom-yeti.py</name>
  <api_key><YETI_API_KEY></api_key>
  <group>syscheck,sshd</group>
  <alert_format>json</alert_format>
</integration>



## Add custom Yeti rules in Wazuh

Create a new rules file:


sudo nano /var/ossec/etc/rules/yeti_rules.xml

<group name="yeti,">
    <rule id="100500" level="0">
        <decoded_as>json</decoded_as>
        <field name="integration">yeti</field>
        <description>yeti integration messages.</description>
        <options>no_full_log</options>
    </rule>

    <rule id="100501" level="12">
        <if_sid>100500</if_sid>
        <field name="yeti.info.source">AbuseCHMalwareBazaaar</field>
        <description>"Yeti Alert - " $(yeti.info.source) detected this file: $(yeti.source.file) </description>
        <group>pci_dss_10.6.1,pci_dss_11.4,gdpr_IV_35.7.d,</group>
        <options>no_full_log</options>
        <mitre>
            <id>T1203</id>
        </mitre>
    </rule>

     <rule id="100502" level="12">
        <if_sid>100500</if_sid>
        <field name="yeti.info.source">AlienVaultIPReputation</field>
        <description>"Yeti Alert - " $(yeti.info.source) detected IP address: $(yeti.source.src_ip) </description>
        <group>pci_dss_10.2.4,pci_dss_10.2.5,</group>
        <options>no_full_log</options>
    </rule>

     <rule id="100503" level="12">
        <if_sid>100500</if_sid>
        <field name="yeti.info.source" type="pcre2">\w</field>
        <description>"Yeti Alert - " $(yeti.info.source) has detected a potential malicious activity </description>
        <options>no_full_log</options>
    </rule>
</group>


echo 'integrator.debug=2' >> /var/ossec/etc/local_internal_options.conf
systemctl restart wazuh-manager

