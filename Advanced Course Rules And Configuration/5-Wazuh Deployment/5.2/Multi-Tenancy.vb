# Multi-tenancy Windows And Linux Endpoints:

1. Edit the `/etc/wazuh-dashboard/opensearch_dashboards.yml` configuration file and make the following changes:
- Set the `opensearch_security.multitenancy.enabled` setting to `true`.

opensearch_security.multitenancy.tenants.preferred: ["Global", "Private"]

You can add tenants here to move them to the top of the list.

opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Global", "Private"]
opensearch_security.readonly_mode.roles: ["kibana_read_only"]


Additionally, you can edit the uiSettings.overrides.defaultRoute to set a default tenant, for example, global, each time a user logs in.

uiSettings.overrides.defaultRoute: /app/wz-home?security_tenant=global

Restart the Wazuh dashboard so changes can take effect.

systemctl restart wazuh-dashboard

### Use Case: Give a User Permissions to Read and Manage a Group of Agents

1. **Adding an Agents Group Label**:
- Log into the Wazuh dashboard as an administrator.
- Select **Server management > Endpoint Groups**.
- Select your group (e.g WIndows), go to **Files**, and click **Edit group configuration**.
- Add a label in the configuration:

Windows

  <agent_config>
    <labels>
      <label key="group">Windows</label>
    </labels>
  </agent_config>



Linux:

  <agent_config>
    <labels>
      <label key="group">Linux</label>
    </labels>
  </agent_config>



{
  "bool": {
    "must": {
      "match": {
        "agent.labels.group": "Windows"
      }
    }
  }
}

{
  "bool": {
    "must": {
      "match": {
        "agent.labels.group": "Linux"
      }
    }
  }
}


