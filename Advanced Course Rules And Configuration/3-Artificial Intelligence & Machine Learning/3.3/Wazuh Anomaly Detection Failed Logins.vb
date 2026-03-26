Wazuh Anomaly Detection: Failed Logins

This guide details the process of creating an anomaly detector on the Wazuh dashboard to identify unusual patterns in unsuccessful login attempts, often indicative of brute-force attacks.
🛠️ 1. Detector Definition

Follow these steps to define the data source and timing for the anomaly detector:

    Navigate to the Anomaly Detection plugin and click Create detector.

    Name: failed-logins-anomaly

    Description: Provide a suitable description for tracking failed login spikes.

    Data Source (Index): wazuh-alerts-*

    Data Filter: Apply rule.groups is not authentication_success.

    Timestamp Field: Select the default timestamp field.

    Detector Interval: 1 minute.

    Window Delay: 1 minute.

🧠 2. Model Configuration

Configure the features that the machine learning model will use to find anomalies:
Feature 1: Source IP Spikes

    Name: failed-logins-srcip

    Feature State: Enabled

    Find anomalies based on: Field value

    Aggregation method: count()

    Field: data.srcip

Feature 2: Agent IP Spikes

    Name: failed-logins-agentip

    Feature State: Enabled

    Find anomalies based on: Field value

    Aggregation method: count()

    Field: agent.ip

⚙️ 3. Detector Jobs

    Select Start real-time detector automatically (recommended).

    This ensures the model begins learning from your live alert stream immediately.

⚔️ 4. Attack Emulation (Verification)

To verify the detector, perform a brute-force attack from a Kali Linux endpoint against an Ubuntu endpoint.


