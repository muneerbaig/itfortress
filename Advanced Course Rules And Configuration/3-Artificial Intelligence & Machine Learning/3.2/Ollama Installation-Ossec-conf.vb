Wazuh server

Perform the following steps on the Wazuh server to set up the Llama 3 LLM.

1. Follow the steps in archiving event logs to enable Wazuh archives, specifically the /var/ossec/logs/archives/archives.json file. The Wazuh archives are required for the threat hunting exercise as they collect and store all logs, whether or not they trigger a rule.

2. Run the following command to install Ollama:

curl -fsSL https://ollama.com/install.sh | sh

3. Install the required Llama 3 LLM model:
ollama pull llama3

4. Install Python3 if you do not already have it installed:
apt install python3 -y
apt install python3-pip -y

5. Install the Python dependencies required to run the script:
pip install paramiko python-daemon langchain langchain-community langchain-ollama langchain-huggingface faiss-cpu sentence-transformers transformers pytz hf_xet fastapi uvicorn 'uvicorn[standard]'

nano /var/ossec/etc/ossec.conf

ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>                                       --change to yes
    <logall_json>yes</logall_json>                             --change to yes
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>15m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
    <update_check>yes</update_check>
  </global>






The Llama 3 model is accessed via a web-based chatbot, which is created after running the script. This section describes how to interact with the Llama 3 LLM via the chatbot.

Follow the steps below to access the Llama 3 model.

1. Launch the /var/ossec/integrations/threat_hunter.py script. The script creates a web service on port 8000 using your Wazuh server IP address:
python3 /var/ossec/integrations/threat_hunter.py

2. Visit http://<WAZUH_SERVER_IP>:8000 from a browser with network connectivity to the Wazuh server and input your credentials. Replace <WAZUH_SERVER_IP> with the IP of your Wazuh server. The following webpage can be seen:

