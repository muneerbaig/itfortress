Wazuh - OpenCTI Integration & Alerting Rules

This phase covers the configuration of the Wazuh Manager to send alerts to the OpenCTI GraphQL API and the implementation of custom rules to categorize threat intelligence hits.
🛠️ Step 1: Manager Configuration

Edit the main configuration file on your Wazuh Manager:

sudo nano /var/ossec/etc/ossec.conf

Find the <ossec_config> section and add (or replace) the following integration block. This uses the OpenCTI API token and hook URL configured in the previous steps:

<integration>
  <name>custom-opencti</name>
  <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event15,sysmon_event22,sysmon_event23,sysmon_event24,sysmon_event25,sysmon_eid3_detections,sysmon_eid22_detections,syscheck_file,syscheck_entry_added,syscheck_entry_modified,ids,osquery,osquery_file,audit_command,auditd</group>
  <alert_format>json</alert_format>
  <api_key>4167f685-f888-438d-bda5-7ae75f995371</api_key>
  <hook_url>http://10.10.30.53:8080/graphql</hook_url>
</integration>


🛡️ Step 2: Custom Alerting Rules

Add the following rules to your local_rules.xml file to process responses coming back from OpenCTI. These rules allow the Wazuh dashboard to display specific IoC matches (indicators, observables, and patterns).

File Path: /var/ossec/etc/rules/local_rules.xml

<group name="threat_intel,">
  
  <rule id="100210" level="10">
    <field name="integration">^opencti$</field>
    <description>OpenCTI Integration Triggered</description>
    <group>opencti,</group>
  </rule>

  <rule id="100211" level="5">
    <if_sid>100210</if_sid>
    <field name="opencti.error">.+</field>
    <description>OpenCTI: Failed to connect to API</description>
    <options>no_full_log</options>
    <group>opencti,opencti_error,</group>
  </rule>

  <rule id="100212" level="12">
    <if_sid>100210</if_sid>
    <field name="opencti.event_type">^indicator_pattern_match$</field>
    <description>OpenCTI: IoC found in threat intel: $(opencti.indicator.name)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>

  <rule id="100213" level="12">
    <if_sid>100210</if_sid>
    <field name="opencti.event_type">^observable_with_indicator$</field>
    <description>OpenCTI: IoC found in threat intel: $(opencti.observable_value)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>

  <rule id="100214" level="10">
    <if_sid>100210</if_sid>
    <field name="opencti.event_type">^observable_with_related_indicator$</field>
    <description>OpenCTI: IoC possibly found in threat intel (related): $(opencti.related.indicator.name)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>

  <rule id="100215" level="10">
    <if_sid>100210</if_sid>
    <field name="opencti.event_type">^indicator_partial_pattern_match$</field>
    <description>OpenCTI: IoC possibly found in threat intel: $(opencti.indicator.name)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>

  <rule id="100216" level="12">
    <if_sid>100210</if_sid>
    <field name="opencti.event_type">^observable_without_indicator$</field>
    <description>OpenCTI: IoC found in threat intel: $(opencti.observable_value)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>

</group>



Next once give save the file,added and give full permission and ownership for both custom-opencti*

chown -R root:wazuh custom-opencti*
chmod 750 custom-opencti*

Once done Restart wazuh-manager,dashboard,indexer:

systemctl restart wazuh-manager wazuh-dashboard wazuh-indexer



