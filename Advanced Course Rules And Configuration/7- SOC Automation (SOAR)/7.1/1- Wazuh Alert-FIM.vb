Wazuh Alert- Malicious File detection

Go to Ossec.conf edit: Add the Scripts:

<integration>
     <name>custom-n8n</name>
     <hook_url>http://10.10.20.50:5678/webhook/agent-online-and-offline-trigger</hook_url>
     <rule_id>550,554,553</rule_id>
     <alert_format>json</alert_format>
  </integration>


IOC: JSON


const body = items[0].json.body || {};
const syscheck = body.syscheck || {};
const rule = body.rule || {};
const full_log = body.full_log || "";

// ----------------------
// 1. Extract HASHES
// ----------------------
const hashes = {
  md5: syscheck.md5_after || null,
  sha1: syscheck.sha1_after || null,
  sha256: syscheck.sha256_after || null
};

// Known empty hashes (ignore)
const EMPTY_HASHES = [
  "d41d8cd98f00b204e9800998ecf8427e",
  "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
];

// ----------------------
// 2. Extract from LOG (Regex)
// ----------------------
const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const domainRegex = /\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;
const urlRegex = /https?:\/\/[^\s]+/g;

// Extract matches
const ips = full_log.match(ipRegex) || [];
const domains = full_log.match(domainRegex) || [];
const urls = full_log.match(urlRegex) || [];

// ----------------------
// 3. IOC PRIORITY LOGIC
// ----------------------
let ioc = null;
let ioc_type = null;

// Priority: SHA256 > SHA1 > MD5 > URL > Domain > IP

if (hashes.sha256 && !EMPTY_HASHES.includes(hashes.sha256)) {
  ioc = hashes.sha256;
  ioc_type = "sha256";
}
else if (hashes.sha1 && !EMPTY_HASHES.includes(hashes.sha1)) {
  ioc = hashes.sha1;
  ioc_type = "sha1";
}
else if (hashes.md5 && !EMPTY_HASHES.includes(hashes.md5)) {
  ioc = hashes.md5;
  ioc_type = "md5";
}
else if (urls.length > 0) {
  ioc = urls[0];
  ioc_type = "url";
}
else if (domains.length > 0) {
  ioc = domains[0];
  ioc_type = "domain";
}
else if (ips.length > 0) {
  ioc = ips[0];
  ioc_type = "ip";
}

// ----------------------
// 4. Alert Context
// ----------------------
const filePath = syscheck.path || null;
const description = rule.description || 'No description';
const agent = body.agent?.name || 'unknown';
const level = rule.level || 0;

// ----------------------
// 5. Smart Classification
// ----------------------
let alert_type = "unknown";

if (rule.groups?.includes("syscheck")) {
  alert_type = "file_integrity";
} else if (rule.groups?.includes("network")) {
  alert_type = "network";
}

// ----------------------
// 6. Final Output
// ----------------------
return [{
  json: {
    type: 'dynamic_alert',

    //  MAIN IOC
    ioc,
    ioc_type,

    // ALL EXTRACTED
    hashes,
    ips,
    domains,
    urls,

    //  CONTEXT
    file_path: filePath,
    description,
    agent,
    level,
    alert_type,

    // RAW ALERT
    full_alert: body
  }
}];



VT:
https://www.virustotal.com/api/v3/files/{{ $json.hashes.sha256 }}


Generate Summary File Json:

const vt = items[0].json || {};
const data = vt.data?.attributes || {};

// Reference the original Wazuh payload directly from the "Webhook" node
const wazuhBody = $('Webhook').first().json.body || {}; 
const agent = wazuhBody.agent || {};
const syscheck = wazuhBody.syscheck || {};
const rule = wazuhBody.rule || {};

const summary = {
  // VirusTotal Intel
  SHA256: vt.data?.id || syscheck.sha256_after || 'N/A',
  Name: data?.meaningful_name || 'Unknown',
  Magic: data?.magic || 'N/A',
  Malicious: data?.last_analysis_stats?.malicious || 0,
  Suspicious: data?.last_analysis_stats?.suspicious || 0,
  Undetected: data?.last_analysis_stats?.undetected || 0,
  Harmless: data?.last_analysis_stats?.harmless || 0,
  Tags: (data?.tags || []).join(', '),
  Reputation: data?.reputation || 0,
  Description: data?.popular_threat_classification?.suggested_threat_label || 'No Label',
  Generated_At: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
  
  // Wazuh Agent & System Details
  Agent_IP: agent.ip || 'N/A',
  Agent_Name: agent.name || 'N/A',
  Agent_ID: agent.id || 'N/A',
  File_Path: syscheck.path || 'N/A',
  File_Owner: syscheck.uname_after || 'N/A',
  Rule_Description: rule.description || 'N/A'
};

// Simple status rule
summary.Status = (summary.Malicious > 0 || summary.Suspicious > 0) ? 'Suspicious' : 'Safe';

return [{ json: { summary } }];


Filter:

{{ $json.summary.Status }} is equal to Suspicious
or
{{ $json.summary.Status }} is equal to Safe


html :

<div style="font-family: 'Segoe UI', Arial, Helvetica, sans-serif; max-width: 700px; margin: auto; border: 1px solid #dcdcdc; border-radius: 10px; overflow: hidden; box-shadow: 0 6px 12px rgba(0,0,0,0.08); background-color: #ffffff;">
    
    <!-- Dynamic Main Header: Red (Malicious), Orange (Suspicious), Green (Safe) -->
    <div style="background-color: {{ $json.summary.Malicious > 0 ? '#d32f2f' : ($json.summary.Status === 'Suspicious' ? '#f57c00' : '#2e7d32') }}; color: white; padding: 22px; text-align: center; border-bottom: 4px solid rgba(0,0,0,0.15);">
        <h2 style="margin: 0; font-size: 26px; text-transform: uppercase; letter-spacing: 1.5px;">
            {{ $json.summary.Malicious > 0 ? '🚨 CRITICAL MALWARE ALERT' : ($json.summary.Status === 'Suspicious' ? '⚠️ SUSPICIOUS FILE DETECTED' : '✅ FILE SCANNED - SAFE') }}
        </h2>
        <p style="margin: 6px 0 0; font-size: 14px; opacity: 0.9;">Generated At: {{ $json.summary.Generated_At }}</p>
    </div>

    <div style="padding: 25px;">
        
        <!-- Top Summary -> Multi-Color Threat Statistics -->
        <table style="width: 100%; border-collapse: separate; border-spacing: 12px 0; margin-bottom: 25px; text-align: center;">
            <tr>
                <td style="padding: 15px 5px; background-color: #ffebee; border: 1px solid #ef9a9a; border-radius: 8px; width: 25%; box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);">
                    <strong style="color: #c62828; font-size: 24px;">{{ $json.summary.Malicious }}</strong><br>
                    <span style="color: #d32f2f; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;">Malicious</span>
                </td>
                <td style="padding: 15px 5px; background-color: #fff3e0; border: 1px solid #ffcc80; border-radius: 8px; width: 25%; box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);">
                    <strong style="color: #ef6c00; font-size: 24px;">{{ $json.summary.Suspicious }}</strong><br>
                    <span style="color: #f57c00; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;">Suspicious</span>
                </td>
                <td style="padding: 15px 5px; background-color: #e8f5e9; border: 1px solid #a5d6a7; border-radius: 8px; width: 25%; box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);">
                    <strong style="color: #2e7d32; font-size: 24px;">{{ $json.summary.Harmless }}</strong><br>
                    <span style="color: #388e3c; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;">Harmless</span>
                </td>
                <td style="padding: 15px 5px; background-color: #f5f5f5; border: 1px solid #e0e0e0; border-radius: 8px; width: 25%; box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);">
                    <strong style="color: #424242; font-size: 24px;">{{ $json.summary.Undetected }}</strong><br>
                    <span style="color: #616161; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;">Undetected</span>
                </td>
            </tr>
        </table>

        <!-- Section 1: Wazuh Endpoint Context (Blue Theme) -->
        <div style="background-color: #f0f4f8; border-left: 5px solid #1976d2; border-radius: 6px; margin-bottom: 25px; overflow: hidden;">
            <div style="background-color: #e3f2fd; padding: 10px 15px; border-bottom: 1px solid #bbdefb; color: #0d47a1; font-weight: bold; font-size: 15px; text-transform: uppercase;">
                🛡️ Endpoint Context (Wazuh)
            </div>
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <th style="padding: 10px 15px; border-bottom: 1px solid #e0e0e0; text-align: left; width: 30%; font-size: 13px; color: #455a64;">Triggered Rule</th>
                    <td style="padding: 10px 15px; border-bottom: 1px solid #e0e0e0; font-size: 14px; font-weight: bold; color: #d32f2f;">{{ $json.summary.Rule_Description }}</td>
                </tr>
                <tr>
                    <th style="padding: 10px 15px; border-bottom: 1px solid #e0e0e0; text-align: left; font-size: 13px; color: #455a64;">Agent Details</th>
                    <td style="padding: 10px 15px; border-bottom: 1px solid #e0e0e0; font-size: 13px; color: #333;">
                        <strong>{{ $json.summary.Agent_Name }}</strong> (ID: {{ $json.summary.Agent_ID }})<br>
                        <span style="color: #1565c0; font-family: monospace; font-size: 14px;">IP: {{ $json.summary.Agent_IP }}</span>
                    </td>
                </tr>
                <tr>
                    <th style="padding: 10px 15px; border-bottom: 1px solid #e0e0e0; text-align: left; font-size: 13px; color: #455a64;">File Path</th>
                    <td style="padding: 10px 15px; border-bottom: 1px solid #e0e0e0; font-size: 13px; font-family: Consolas, monospace; background-color: #ffffff; color: #c2185b; word-break: break-all;">{{ $json.summary.File_Path }}</td>
                </tr>
                <tr>
                    <th style="padding: 10px 15px; text-align: left; font-size: 13px; color: #455a64;">File Owner</th>
                    <td style="padding: 10px 15px; font-size: 13px; color: #333;"><code>{{ $json.summary.File_Owner }}</code></td>
                </tr>
            </table>
        </div>

        <!-- Section 2: VirusTotal Intel Context (Purple/Grey Theme) -->
        <div style="background-color: #fcfcfc; border-left: 5px solid #673ab7; border-radius: 6px; overflow: hidden; border-top: 1px solid #eeeeee; border-right: 1px solid #eeeeee; border-bottom: 1px solid #eeeeee;">
            <div style="background-color: #f3e5f5; padding: 10px 15px; border-bottom: 1px solid #e1bee7; color: #4a148c; font-weight: bold; font-size: 15px; text-transform: uppercase;">
                🔬 Threat Intelligence (VirusTotal)
            </div>
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <th style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; text-align: left; width: 30%; font-size: 13px; color: #616161;">Status</th>
                    <td style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; font-size: 13px;">
                        <span style="background-color: {{ $json.summary.Status === 'Suspicious' ? '#fff3e0' : ($json.summary.Malicious > 0 ? '#ffebee' : '#e8f5e9') }}; color: {{ $json.summary.Status === 'Suspicious' ? '#e65100' : ($json.summary.Malicious > 0 ? '#c62828' : '#2e7d32') }}; padding: 4px 10px; border-radius: 12px; font-weight: bold; text-transform: uppercase; font-size: 11px;">
                            {{ $json.summary.Status }}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; text-align: left; font-size: 13px; color: #616161;">Target File Name</th>
                    <td style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; font-size: 13px; font-weight: bold; color: #333;">{{ $json.summary.Name }}</td>
                </tr>
                <tr>
                    <th style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; text-align: left; font-size: 13px; color: #616161;">SHA256</th>
                    <td style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; font-size: 12px; font-family: Consolas, monospace; color: #555; word-break: break-all;">{{ $json.summary.SHA256 }}</td>
                </tr>
                <tr>
                    <th style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; text-align: left; font-size: 13px; color: #616161;">Threat Label</th>
                    <td style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; font-size: 13px; color: #d32f2f; font-weight: bold;">{{ $json.summary.Description }}</td>
                </tr>
                <tr>
                    <th style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; text-align: left; font-size: 13px; color: #616161;">File Magic</th>
                    <td style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; font-size: 13px; color: #333;">{{ $json.summary.Magic }}</td>
                </tr>
                <tr>
                    <th style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; text-align: left; font-size: 13px; color: #616161;">VT Reputation</th>
                    <!-- Dynamic Reputation Color: Red if < 0, Green if > 0 -->
                    <td style="padding: 10px 15px; border-bottom: 1px solid #eeeeee; font-size: 14px; font-weight: bold; color: {{ $json.summary.Reputation < 0 ? '#c62828' : ($json.summary.Reputation > 0 ? '#2e7d32' : '#757575') }};">{{ $json.summary.Reputation }}</td>
                </tr>
                <tr>
                    <th style="padding: 10px 15px; text-align: left; font-size: 13px; color: #616161;">Behavior Tags</th>
                    <td style="padding: 10px 15px; font-size: 13px;">
                        <!-- Dynamic multi-colored Tag Generation based on string parsing -->
                        {{ $json.summary.Tags && $json.summary.Tags !== 'N/A' ? $json.summary.Tags.split(', ').map(tag => `<span style="background-color: #f3e5f5; border: 1px solid #ce93d8; color: #6a1b9a; padding: 3px 8px; border-radius: 10px; margin: 2px 4px 2px 0; display: inline-block; font-size: 11px; white-space: nowrap;">${tag}</span>`).join('') : '<span style="color:#999; font-style:italic;">No behavioral tags available</span>' }}
                    </td>
                </tr>
            </table>
        </div>

        <!-- Footer -->
        <div style="margin-top: 25px; border-top: 1px solid #e0e0e0; padding-top: 15px; text-align: center;">
            <p style="font-size: 11px; color: #888; margin: 0; text-transform: uppercase; letter-spacing: 0.5px;">
                ⚡ Generated by n8n SOAR Automation
            </p>
        </div>
    </div>
</div>
