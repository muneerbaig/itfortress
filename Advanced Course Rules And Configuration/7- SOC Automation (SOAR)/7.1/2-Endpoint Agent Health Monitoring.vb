Endpoint Agent Health Monitoring(Online & Offline Detection Automation)

Go to Ossec.conf edit: Add the Scripts:

<integration>
     <name>custom-n8n</name>
     <hook_url>http://10.10.20.50:5678/webhook/agent-online-and-offline-trigger</hook_url>
     <rule_id>503,506</rule_id>
     <alert_format>json</alert_format>
  </integration>


Switch Node:

String T : match regex:

^(503|506)$   or
503|506


# Agent Online & Offline Code Node

### ✅ Purpose

Core processing engine.

### What it does

Transforms raw alert into structured data.

### Processing includes:

- Extract agent name
- Extract agent ID
- Detect status (online/offline)
- Calculate downtime duration
- Normalize timestamps


// Get incoming Wazuh alert
const alert = $json.body || $json;

// Extract rule id
const ruleId = String(alert?.rule?.id || "");

// Rule mapping
const ruleMap = {
    "506": {
        status: "OFFLINE",
        online: false,
        severity: "high",
        message: "Wazuh agent stopped (Agent Offline)"
    },
    "503": {
        status: "ONLINE",
        online: true,
        severity: "info",
        message: "Wazuh agent connected (Agent Online)"
    }
};

// Default values
const mapped = ruleMap[ruleId] || {
    status: "UNKNOWN",
    online: null,
    severity: "low",
    message: "Unhandled agent state event"
};

// Output normalized data
return [
{
    json: {
        event_type: "agent_status_monitoring",

        timestamp: alert.timestamp,
        rule_id: ruleId,
        rule_description: alert?.rule?.description,

        agent: {
            id: alert?.agent?.id,
            name: alert?.agent?.name,
            ip: alert?.agent?.ip
        },

        manager: alert?.manager?.name,

        status: mapped.status,
        agent_online: mapped.online,   // ✅ TRUE / FALSE here
        severity: mapped.severity,
        message: mapped.message,

        mitre: alert?.rule?.mitre || {},
        raw_log: alert.full_log
    }
}
];


IF Condition Node (Decision Engine)

{{json.status}}
ONLINE 
OR
{{json.status}}
OFFLINE


 Agent Online & Offline HTML Trigger

 <!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#e9edf2;font-family:Arial,Helvetica,sans-serif;">

<!-- FULL WIDTH WRAPPER -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"
style="margin:0;padding:0;background:#e9edf2;border-collapse:collapse;">
<tr>
<td align="center" style="padding:0;margin:0;">

<!-- MAIN CARD (NO OUTER MARGIN) -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"
style="max-width:720px;background:#ffffff;border-collapse:collapse;">

<!-- HEADER -->
<tr>
<td style="padding:18px 22px;
background:linear-gradient(90deg,#1c2b33,#2c5364);
color:#ffffff;">

<h2 style="margin:0;font-size:22px;">🚨 Wazuh Agent Status Alert</h2>
<div style="font-size:13px;opacity:0.9;">
Real-Time Agent Monitoring
</div>

</td>
</tr>

<!-- STATUS BAR AUTO COLOR -->
<tr>
<td style="
padding:14px;
text-align:center;
font-weight:bold;
font-size:15px;
color:#ffffff;
background:
{{ $json.rule_id == '503'
   ? '#28a745'
   : '#ff3b3b' }};
">

{{ $json.rule_id == '503'
   ? '✅ AGENT ONLINE'
   : '❌ AGENT OFFLINE' }}

</td>
</tr>

<!-- INCIDENT SUMMARY -->
<tr>
<td style="padding:20px;">

<h3 style="margin:0 0 12px;color:#2c5364;">📌 Incident Summary</h3>

<table width="100%" cellpadding="6" cellspacing="0"
style="border-collapse:collapse;font-size:14px;">

<tr style="background:#f3f6fa;">
<td width="35%"><b>Event Type</b></td>
<td>{{ $json.event_type }}</td>
</tr>

<tr>
<td><b>Timestamp</b></td>
<td>{{ $json.timestamp }}</td>
</tr>

<tr style="background:#f3f6fa;">
<td><b>Rule ID</b></td>
<td>{{ $json.rule_id }}</td>
</tr>

<tr>
<td><b>Description</b></td>
<td>{{ $json.rule_description }}</td>
</tr>

<tr style="background:#f3f6fa;">
<td><b>Status</b></td>
<td style="
font-weight:bold;
color:
{{ $json.rule_id == '503'
   ? '#28a745'
   : '#ff3b3b' }};
">
{{ $json.status }}
</td>
</tr>

<tr>
<td><b>Severity</b></td>
<td>{{ $json.severity }}</td>
</tr>

</table>

</td>
</tr>

<!-- AGENT INFO -->
<tr>
<td style="padding:20px;background:#f9fbfd;">

<h3 style="margin:0 0 12px;color:#2c5364;">🖥 Agent Information</h3>

<table width="100%" cellpadding="6" cellspacing="0"
style="border-collapse:collapse;font-size:14px;">

<tr>
<td width="35%"><b>Agent ID</b></td>
<td>{{ $json.agent.id }}</td>
</tr>

<tr style="background:#f3f6fa;">
<td><b>Agent Name</b></td>
<td>{{ $json.agent.name }}</td>
</tr>

<tr>
<td><b>Agent IP</b></td>
<td>{{ $json.agent.ip }}</td>
</tr>

<tr style="background:#f3f6fa;">
<td><b>Manager</b></td>
<td>{{ $json.manager }}</td>
</tr>

</table>

</td>
</tr>

<!-- MITRE -->
<tr>
<td style="padding:20px;">

<h3 style="margin:0 0 12px;color:#2c5364;">🎯 MITRE ATT&CK Mapping</h3>

<table width="100%" cellpadding="6" cellspacing="0"
style="border-collapse:collapse;font-size:14px;">

<tr style="background:#f3f6fa;">
<td width="35%"><b>Tactic</b></td>
<td>{{ $json.mitre.tactic[0] }}</td>
</tr>

<tr>
<td><b>Technique</b></td>
<td>{{ $json.mitre.technique[0] }}</td>
</tr>

<tr style="background:#f3f6fa;">
<td><b>Technique ID</b></td>
<td>{{ $json.mitre.id[0] }}</td>
</tr>

</table>

</td>
</tr>

<!-- RAW LOG -->
<tr>
<td style="
padding:18px;
background:#111827;
color:#e5e7eb;
font-family:monospace;
font-size:13px;
word-break:break-word;">

<b>Raw Log</b><br><br>
{{ $json.raw_log }}

</td>
</tr>

<!-- FOOTER -->
<tr>
<td style="
background:#1c2b33;
color:#ffffff;
text-align:center;
padding:12px;
font-size:12px;">

SOC Automation • Wazuh + n8n

</td>
</tr>

</table>

</td>
</tr>
</table>

</body>
</html>

