File Permission and Ownership 

chown root:wazuh custom-misp custom-misp*
chmod 750 custom-misp custom-misp*

Misp RULE GROUPS:

nano /var/ossec/etc/rules/local-rules.xml

<!-- MISP -->

<group name="misp,">
  <rule id="100620" level="10">
    <field name="integration">misp</field>
    <match>misp</match>
    <description>MISP Events</description>
    <options>no_full_log</options>
  </rule>
  <rule id="100621" level="5">
    <if_sid>100620</if_sid>
    <field name="misp.error">\.+</field>
    <description>MISP - Error connecting to API</description>
    <options>no_full_log</options>
    <group>misp_error,</group>
  </rule>
  <rule id="100622" level="12">
    <field name="misp.category">\.+</field>
    <description>MISP - IoC found in Threat Intel - Category: $(misp.category), Attribute: $(misp.value)</description>
    <options>no_full_log</options>
    <group>misp_alert,</group>
  </rule>
</group>

Add The ossec.conf scripts:

nano /var/ossec/etc/ossec.conf

<integration>
    <name>custom-misp</name>
     <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event11,sysmon_event15,sysmon_event22,syscheck_entry_added</group>
    <alert_format>json</alert_format>
 </integration>