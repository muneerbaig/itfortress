Wazuh-MCP Integration for Claude Desktop

This guide covers the installation of the Wazuh MCP Server, which acts as a bridge between the Wazuh SIEM platform and AI assistants like Claude Desktop. This allows for natural language querying of alerts, logs, and metrics.

    ⚠️ Important Note: > * Do not download or install agents on client machines for this integration.

        This installation must be performed on your Ubuntu Server endpoints.

        Do not install as root. Run all commands as a Normal User to avoid permission errors.

🏗️ 1. Overview

The Wazuh MCP Server converts Wazuh data (alerts, logs, and metrics) into a format that AI can understand using the Model Context Protocol (MCP). This enables Claude Desktop to interact with your Wazuh data directly.
🚀 2. Installation Steps

Expect the installation to take approximately 15–20 minutes.
Step A: Clone the Repository

Navigate to your Downloads directory and clone the integration project:

cd ~/Downloads
git clone https://github.com/iamblacklight/wazuh-claude-integration.git
cd wazuh-claude-integration

Step B: Run the Installer

Ensure the script is executable and run it as a normal user:

chmod +x install.sh
./install.sh

⚙️ 3. Configuration

Add the following configuration block to your Claude Desktop configuration file (typically located at ~/.config/Claude/claude_desktop_config.json).

Note: Update the /path/to/mcp-server-wazuh and your credentials accordingly.


{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/mcp-server-wazuh",
      "args": [],
      "env": {
        "WAZUH_API_HOST": "localhost",
        "WAZUH_API_PORT": "55000",
        "WAZUH_API_USERNAME": "wazuh-wui",
        "WAZUH_API_PASSWORD": "your_wazuh_api_password",
        "WAZUH_INDEXER_HOST": "localhost",
        "WAZUH_INDEXER_PORT": "9200",
        "WAZUH_INDEXER_USERNAME": "admin",
        "WAZUH_INDEXER_PASSWORD": "YOUR_INDEXER_PASSWORD",
        "WAZUH_VERIFY_SSL": "false",
        "WAZUH_TEST_PROTOCOL": "https",
        "RUST_LOG": "info"
      }
    }
  }
}



🔄 4. Apply & Restart Services

After saving your configuration, restart the Wazuh Manager and relaunch Claude Desktop.
Restart Wazuh Manager

sudo systemctl restart wazuh-manager

Relaunch Claude Desktop

Force quit any background processes and restart the application as a Normal User:

# Force quit background processes
pkill -f claude

# Relaunch the application
claude-desktop &


1. Alert Management (4 tools)
get_wazuh_alerts - Retrieve security alerts with filtering
get_wazuh_alert_summary - Alert summaries and statistics
analyze_alert_patterns - AI-powered pattern analysis
search_security_events - Advanced security event search
Agent Management (6 tools)
get_wazuh_agents - Agent information and status
get_wazuh_running_agents - Active agents overview
check_agent_health - Comprehensive agent health validation
get_agent_processes - Running processes per agent
get_agent_ports - Open ports and services per agent
get_agent_configuration - Detailed agent configuration

