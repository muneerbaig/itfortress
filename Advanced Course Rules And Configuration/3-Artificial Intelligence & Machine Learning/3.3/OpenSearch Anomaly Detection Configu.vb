🕵️ OpenSearch Anomaly Detection Configuration for Wazuh

This guide outlines the standard workflow for configuring the OpenSearch Anomaly Detection plugin to ingest and analyze Wazuh data streams (wazuh-alerts-*, wazuh-archives-*, etc.).
🏗️ 1. Define Detector

The detector is the engine that monitors your data stream.

    Navigate: Go to OpenSearch Plugins -> Anomaly Detection.

    Initialize: Click Create detector.

    Details: * Name: Give it a clear, unique name.

        Description: Briefly explain what this detector targets (e.g., "Monitoring spikes in firewall denies").

    Data Source: Select your index (e.g., wazuh-alerts-*).

    Data Filter: (Optional) Add filters to narrow the scope (e.g., manager.name is wazuh-master).

    Timestamp: Select the @timestamp or timestamp field.

    Timing:

        Detector Interval: How often the model runs (e.g., 1 min to 5 mins).

        Window Delay: Buffer time to ensure all logs have arrived from agents.

    💡 Note: Lower intervals provide real-time results but consume more CPU/RAM. For low-traffic environments, use a higher interval (e.g., 10 mins) to give the model more data points to learn from.

🧠 2. Configure Model (Features)

Features are the specific "signals" the AI looks at to find patterns.

    Feature Name: Define a unique name (e.g., high_volume_login_failures).

    Feature State: Ensure this is toggled to Enabled.

    Anomaly Criteria: * Select Field value (Standard) or Custom expression (Advanced JSON).

    Aggregation: Choose how to calculate the data:

        count(): Best for frequency (e.g., number of alerts).

        sum(): Best for volumes (e.g., total bytes transferred).

        average()/min()/max(): Best for performance metrics.

    Index Field: Choose the specific field to watch (e.g., data.srcip).

    ⚠️ Constraint: You can add a maximum of 5 features per detector.

⚡ 3. Set Up Detector Jobs

Choose how you want to process the data:

    Real-time Detection: Continuously monitors incoming Wazuh data to find anomalies as they happen.

    Historical Analysis: (Optional) Use this to look back at weeks or months of old data to find patterns you might have missed in the past.

✅ 4. Review and Create

Verify the three main pillars of your detector:

    Detector Settings (Data source and timing).

    Model Configuration (The features and aggregations).

    Detector Schedule (When it runs).

Click Create detector. You will receive a success message once the model initializes.
📈 How it Works (Visual Logic)

Once configured, the plugin follows this cycle:
Ingest Data ➡️ Feature Extraction ➡️ RCF Model Analysis ➡️ Anomaly Grade/Confidence Output ➡️ Dashboard Visualization.