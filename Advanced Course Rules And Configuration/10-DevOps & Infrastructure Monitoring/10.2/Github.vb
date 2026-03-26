Requirements for monitoring GitHub audit logs

You need the following requirements on GitHub to access the audit logs with Wazuh.

    GitHub organization: You can only view audit logs for GitHub organizations.

    GitHub Enterprise Cloud subscription: Only organizations with a GitHub Enterprise Cloud subscription can use the GitHub audit log REST API.

Creating a personal access token on GitHub

Take the following steps on GitHub to generate the required personal access token:

    Sign into GitHub with an account that belongs to the organization owner.

    Navigate to https://github.com/settings/tokens/new to create a new personal access token.

   
    Include a descriptive note for the personal access token, and select an expiration time.


Scroll down, select audit_log, and click Generate token.

Copy the newly generated personal access token.


Configure Wazuh to pull GitHub logs

Perform the following steps to allow Wazuh to monitor, collect, and analyze the GitHub audit logs. You can either configure the Wazuh module for GitHub in the Wazuh server or the Wazuh agent.

    Append the following configuration to the /var/ossec/etc/ossec.conf file on the Wazuh server.

<ossec_config>
  <github>
    <enabled>yes</enabled>
    <interval>1m</interval>
    <time_delay>1m</time_delay>
    <curl_max_size>1M</curl_max_size>
    <only_future_events>yes</only_future_events>
    <api_auth>
      <org_name><ORG_NAME></org_name>
      <api_token><API_TOKEN></api_token>
    </api_auth>
    <api_parameters>
      <event_type>all</event_type>
    </api_parameters>
  </github>
</ossec_config>



Restart the Wazuh manager or agent service to apply the changes:

    Wazuh manager

    systemctl restart wazuh-manager

