### Updated `custom-opencti.py` (Linux Support Added)

Paste this logic into your script at `/var/ossec/integrations/custom-opencti.py`. 

nano /var/ossec/integrations/custom-opencti.py

#!/usr/bin/env python3
# Copyright Ramkumar 2026, ITFORTRESS 
# Modified: improved IOC extraction + fixed hash/file/filename queries + fixed filename false-positive indicators
# Additional fix: extract IPv4/IPv6 and domains from Sysmon Event 1 commandLine/parentCommandLine (e.g., ping.exe 45.156.129.125, nslookup bitcoinrollups.xyz)

import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import datetime
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import re
import traceback

max_ind_alerts = 3
max_obs_alerts = 3

debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
url = ''

regex_sha256 = re.compile(r'\b[A-Fa-f0-9]{64}\b')
regex_sha1 = re.compile(r'\b[A-Fa-f0-9]{40}\b')
regex_md5 = re.compile(r'\b[A-Fa-f0-9]{32}\b')

# NEW: IP regexes for command-line extraction
regex_ipv4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
regex_ipv6 = re.compile(r'(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])')

# NEW: domain / hostname regex for command-line extraction (nslookup, ping domain, curl, etc.)
regex_domain = re.compile(
    r'\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b'
)

sha256_sysmon_event_regex = re.compile(
    r"sysmon_(?:(?:event_?|eid)(?:1|6|7|15|23|24|25)|process-anomalies)"
)
sysmon_event3_regex = re.compile(r"sysmon_(?:event|eid)3")
sysmon_event22_regex = re.compile(r"sysmon_(?:event22|event_22|eid22)")

log_file = f"{pwd}/logs/integrations.log"
socket_addr = f"{pwd}/queue/sockets/queue"

dns_results_regex = re.compile(r"type:\s*\d+\s*[^;]+|([^\s;]+)")


def main(args):
    global url, debug_enabled
    alert_path = args[1]
    token = args[2]
    url = args[3]
    debug_enabled = len(args) > 4 and args[4] == 'debug'

    debug(f"# Starting, alert_path={alert_path}, url={url}")

    with open(alert_path, errors='ignore') as alert_file:
        alert = json.load(alert_file)

    debug("# Processing alert:")
    debug(alert)

    for new_alert in query_opencti(alert, url, token):
        send_event(new_alert, alert.get('agent'))


def debug(msg, do_log=False):
    do_log |= debug_enabled
    if not do_log:
        return
    now = time.strftime('%a %b %d %H:%M:%S %Z %Y')
    with open(log_file, 'a') as f:
        f.write(f"{now}: {msg}\n")


def log(msg):
    debug(msg, do_log=True)


def remove_empties(value):
    def empty(v):
        return False if isinstance(v, bool) else not bool(v)

    if isinstance(value, list):
        return [x for x in (remove_empties(x) for x in value) if not empty(x)]
    if isinstance(value, dict):
        return {
            k: v for (k, v) in ((k, remove_empties(v)) for k, v in value.items())
            if not empty(v)
        }
    return value


def simplify_objectlist(output, listKey, valueKey, newKey):
    if listKey not in output:
        output[newKey] = []
        return

    if isinstance(output[listKey], dict) and 'edges' in output[listKey]:
        edges = output[listKey]['edges']
        output[newKey] = [item[valueKey] for edge in edges for _, item in edge.items()]
    else:
        output[newKey] = [item[valueKey] for item in output[listKey]]

    if newKey != listKey and listKey in output:
        del output[listKey]


def format_dns_results(results):
    def unmap_ipv6(addr):
        if isinstance(addr, ipaddress.IPv4Address):
            return addr
        v4 = addr.ipv4_mapped
        return v4 if v4 else addr

    try:
        results = list(filter(len, dns_results_regex.findall(results)))
        results = list(map(lambda x: unmap_ipv6(ipaddress.ip_address(x)).exploded, results))
        return list(filter(lambda x: ipaddress.ip_address(x).is_global, results))
    except Exception:
        return []


def packetbeat_dns(alert):
    try:
        return (
            'data' in alert and
            'method' in alert['data'] and
            'dns' in alert['data'] and
            alert['data']['method'] == 'QUERY'
        )
    except Exception:
        return False


def filter_packetbeat_dns(answers):
    out = []
    for r in answers:
        try:
            if r.get('type') in ('A', 'AAAA') and ipaddress.ip_address(r.get('data', '')).is_global:
                out.append(r['data'])
        except Exception:
            pass
    return out


def indicator_sort_func(x):
    return (
        x.get('revoked', False),
        not x.get('x_opencti_detection', False),
        -int(x.get('x_opencti_score', 0) or 0),
        -int(x.get('confidence', 0) or 0),
        datetime.strptime(x.get('valid_until', '1970-01-01T00:00:00.000Z'),
                          '%Y-%m-%dT%H:%M:%S.%fZ') <= datetime.now()
    )


def sort_indicators(indicators):
    return sorted(indicators, key=indicator_sort_func)


def modify_indicator(indicator):
    if indicator:
        simplify_objectlist(indicator, 'objectLabel', 'value', 'labels')
        simplify_objectlist(indicator, 'killChainPhases', 'kill_chain_name', 'killChainPhases')
        if 'externalReferences' in indicator:
            simplify_objectlist(indicator, 'externalReferences', 'url', 'externalReferences')
    return indicator


def indicator_link(indicator):
    return url.removesuffix('graphql') + f"dashboard/observations/indicators/{indicator['id']}"


def modify_observable(observable, indicators):
    observable['observable_link'] = url.removesuffix('graphql') + f"dashboard/observations/observables/{observable['id']}"
    simplify_objectlist(observable, 'externalReferences', 'url', 'externalReferences')
    simplify_objectlist(observable, 'objectLabel', 'value', 'labels')

    observable['indicator'] = next(iter(indicators), None)
    observable['multipleIndicators'] = len(indicators) > 1
    if observable['indicator']:
        observable['indicator_link'] = indicator_link(observable['indicator'])
    modify_indicator(observable['indicator'])

    if 'indicators' in observable:
        del observable['indicators']
    if 'stixCoreRelationships' in observable:
        del observable['stixCoreRelationships']


def relationship_with_indicators(node):
    related = []
    try:
        for relationship in node.get('stixCoreRelationships', {}).get('edges', []):
            relnode = relationship.get('node', {})
            relto = relnode.get('related', {})
            ind_edges = relto.get('indicators', {}).get('edges', [])
            if ind_edges:
                inds = sort_indicators([x['node'] for x in ind_edges])
                best = modify_indicator(next(iter(inds), None))
                related.append(dict(
                    id=relto.get('id'),
                    type=relnode.get('type'),
                    relationship=relnode.get('relationship_type'),
                    value=relto.get('value'),
                    indicator=best,
                    multipleIndicators=len(ind_edges) > 1,
                ))
                if best:
                    related[-1]['indicator_link'] = indicator_link(best)
    except Exception:
        pass

    return next(iter(sorted(related, key=lambda x: indicator_sort_func(x['indicator']))), None)


def add_context(source_event, event):
    event.setdefault('opencti', {})
    event['opencti'].setdefault('source', {})
    src = event['opencti']['source']

    src['alert_id'] = source_event.get('id')
    src['rule_id'] = source_event.get('rule', {}).get('id')

    if 'syscheck' in source_event:
        src['file'] = source_event['syscheck'].get('path')
        src['md5'] = source_event['syscheck'].get('md5_after')
        src['sha1'] = source_event['syscheck'].get('sha1_after')
        src['sha256'] = source_event['syscheck'].get('sha256_after')

    data = source_event.get('data', {})
    for key in [
        'in_iface', 'srcintf', 'src_ip', 'srcip', 'src_mac', 'srcmac',
        'src_port', 'srcport', 'dest_ip', 'dstip', 'dst_mac', 'dstmac',
        'dest_port', 'dstport', 'dstintf', 'proto', 'app_proto'
    ]:
        if key in data:
            src[key] = data[key]

    if packetbeat_dns(source_event):
        try:
            src['queryName'] = data['dns']['question']['name']
            if 'answers' in data['dns']:
                src['queryResults'] = ';'.join(map(lambda x: x.get('data', ''), data['dns']['answers']))
        except Exception:
            pass

    if 'win' in data and 'eventdata' in data['win']:
        ev = data['win']['eventdata']
        for key in ['queryName', 'queryResults', 'image', 'DestinationIp', 'destinationIp',
                    'TargetFilename', 'targetFilename', 'commandLine', 'parentCommandLine']:
            if key in ev:
                src[key] = ev[key]

    if 'audit' in data and 'execve' in data['audit']:
        execve = data['audit']['execve']
        try:
            src['execve'] = ' '.join(execve[k] for k in sorted(execve.keys()))
        except Exception:
            src['execve'] = str(execve)


def send_event(msg, agent=None):
    if not agent or agent.get('id') == '000':
        string = f"1:opencti:{json.dumps(msg)}"
    else:
        string = "1:[{0}] ({1}) {2}->opencti:{3}".format(
            agent.get('id'),
            agent.get('name'),
            agent.get('ip', 'any'),
            json.dumps(msg)
        )

    debug("# Event:")
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()


def send_error_event(msg, agent=None):
    send_event({'integration': 'opencti', 'opencti': {'error': msg, 'event_type': 'error'}}, agent)


def ind_ip_pattern(string):
    ip = ipaddress.ip_address(string)
    if ip.version == 6:
        return f"[ipv6-addr:value = '{string}']"
    return f"[ipv4-addr:value = '{string}']"


def extract_iocs(alert):
    iocs = []
    groups = alert.get('rule', {}).get('groups', []) or []
    data = alert.get('data', {}) or {}

    def add(t, v):
        if v and isinstance(v, str):
            iocs.append({'type': t, 'value': v})

    # Syscheck file
    if 'syscheck_file' in groups and 'syscheck' in alert:
        sc = alert['syscheck']
        add('filename', sc.get('path'))
        add('sha256', sc.get('sha256_after'))
        add('sha1', sc.get('sha1_after'))
        add('md5', sc.get('md5_after'))

    # Sysmon hashes + filename + commandLine IPs/domains (covers Event 1: ping/nslookup/etc.)
    if any(True for _ in filter(sha256_sysmon_event_regex.match, groups)):
        try:
            hashes = data['win']['eventdata'].get('hashes', '')
            m = regex_sha256.search(hashes)
            if m:
                add('sha256', m.group(0))
            m1 = regex_sha1.search(hashes)
            if m1:
                add('sha1', m1.group(0))
            m2 = regex_md5.search(hashes)
            if m2:
                add('md5', m2.group(0))
        except Exception:
            pass

        try:
            ev = data['win']['eventdata']
            add('filename', ev.get('image') or ev.get('Image'))
            add('filename', ev.get('TargetFilename') or ev.get('targetFilename'))

            # Extract IPs and domains from command lines
            cmd = ev.get('commandLine') or ev.get('CommandLine') or ''
            parent_cmd = ev.get('parentCommandLine') or ev.get('ParentCommandLine') or ''
            for text in (cmd, parent_cmd):
                if not text:
                    continue

                # IPs
                for ip_s in regex_ipv4.findall(text):
                    try:
                        ip = ipaddress.ip_address(ip_s)
                        if ip.is_global:
                            add('ipv4', ip_s)
                    except Exception:
                        pass
                for ip_s in regex_ipv6.findall(text):
                    try:
                        ip = ipaddress.ip_address(ip_s)
                        if ip.is_global:
                            add('ipv6', ip_s)
                    except Exception:
                        pass

                # NEW: domains/hostnames (e.g., nslookup bitcoinrollups.xyz)
                for dom in regex_domain.findall(text):
                    d = dom.strip().lower().strip('.')
                    if '.' in d and not d.endswith(('.local', '.lan')):
                        add('domain', d)
                        add('hostname', d)
        except Exception:
            pass

    # Sysmon event 3 (network)
    if any(True for _ in filter(sysmon_event3_regex.match, groups)):
        for k in ('destinationIp', 'DestinationIp', 'dest_ip', 'dstip'):
            try:
                v = data['win']['eventdata'].get(k) if 'win' in data else data.get(k)
                if v:
                    ip = ipaddress.ip_address(v)
                    if ip.is_global:
                        add('ipv6' if ip.version == 6 else 'ipv4', v)
                    break
            except Exception:
                continue

    # Sysmon event 22 (DNS)
    if any(True for _ in filter(sysmon_event22_regex.match, groups)):
        try:
            ev = data['win']['eventdata']
            q = ev.get('queryName')
            if q:
                add('domain', q)
                add('hostname', q)
            results = format_dns_results(ev.get('queryResults', ''))
            for r in results:
                ip = ipaddress.ip_address(r)
                add('ipv6' if ip.version == 6 else 'ipv4', r)
        except Exception:
            pass

    # ids
    if 'ids' in groups:
        if packetbeat_dns(alert):
            try:
                q = data['dns']['question']['name']
                add('domain', q)
                add('hostname', q)
                answers = filter_packetbeat_dns(data['dns'].get('answers', []))
                for a in answers:
                    ip = ipaddress.ip_address(a)
                    add('ipv6' if ip.version == 6 else 'ipv4', a)
            except Exception:
                pass
        else:
            for k in ('dest_ip', 'dstip', 'src_ip', 'srcip'):
                v = data.get(k)
                try:
                    if v and ipaddress.ip_address(v).is_global:
                        ip = ipaddress.ip_address(v)
                        add('ipv6' if ip.version == 6 else 'ipv4', v)
                        break
                except Exception:
                    pass

    # osquery file
    if any(x in groups for x in ['osquery', 'osquery_file']):
        try:
            cols = data['osquery']['columns']
            add('sha256', cols.get('sha256'))
            add('filename', cols.get('path') or cols.get('name'))
        except Exception:
            pass

    # audit command URLs
    if 'audit_command' in groups:
        try:
            execve = data['audit']['execve']
            for val in execve.values():
                if isinstance(val, str) and val.startswith('http'):
                    add('url', val)
        except Exception:
            pass

    seen = set()
    out = []
    for x in iocs:
        key = (x['type'], x['value'])
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def build_opencti_filters(ioc):
    t = ioc['type']
    v = ioc['value']

    obs_key = 'value'
    obs_values = [v]
    ind_patterns = []
    file_name_values = []

    if t in ('ipv4', 'ipv6'):
        ind_patterns = [ind_ip_pattern(v)]
    elif t == 'domain':
        ind_patterns = [f"[domain-name:value = '{v}']"]
    elif t == 'hostname':
        ind_patterns = [f"[hostname:value = '{v}']"]
    elif t == 'url':
        ind_patterns = [f"[url:value = '{v}']"]
    elif t in ('sha256', 'sha1', 'md5'):
        alg = {'sha256': 'SHA-256', 'sha1': 'SHA-1', 'md5': 'MD5'}[t]
        obs_key = f"hashes.{alg}"
        obs_values = [v]
        ind_patterns = [f"[file:hashes.'{alg}' = '{v}']"]
    elif t == 'filename':
        base = os.path.basename(v.replace("\\", "/"))
        if base:
            file_name_values = [base]
            obs_values = [base]
        else:
            file_name_values = [v]
            obs_values = [v]
        ind_patterns = []
        obs_key = 'value'

    return obs_key, obs_values, ind_patterns, file_name_values


def query_opencti(alert, url, token):
    groups = alert.get('rule', {}).get('groups', []) or []
    iocs = extract_iocs(alert)

    if not iocs:
        debug(f"# No IOCs extracted for groups={groups}, skipping")
        return []

    query_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'Accept': '*/*'
    }

    new_alerts_all = []

    for ioc in iocs[:10]:
        obs_key, obs_values, ind_filter, file_name_values = build_opencti_filters(ioc)

        debug(f"# Querying OpenCTI for IOC {ioc} using obs_key={obs_key}, obs_values={obs_values}, ind_filter={ind_filter}, file_name_values={file_name_values}")

        obs_filters = [{"key": obs_key, "values": obs_values}]

        obs_filter_groups = []
        if file_name_values:
            obs_filter_groups.append({
                "mode": "or",
                "filters": [
                    {"key": "name", "values": file_name_values},
                    {"key": "x_opencti_additional_names", "values": file_name_values},
                ],
                "filterGroups": []
            })

        ind_var = {
            "mode": "and",
            "filterGroups": [],
            "filters": [{"key": "id", "values": ["__never__"]}]
        }
        if ind_filter:
            ind_var = {
                "mode": "and",
                "filterGroups": [],
                "filters": [
                    {"key": "pattern_type", "values": ["stix"]},
                    {"mode": "or", "key": "pattern", "values": ind_filter},
                ]
            }

        api_json_body = {
            'query': '''
            fragment Labels on StixCoreObject {
              objectLabel { value }
            }

            fragment Object on StixCoreObject {
              id
              type: entity_type
              created_at
              updated_at
              createdBy {
                ... on Identity {
                  id
                  standard_id
                  identity_class
                  name
                }
                ... on Organization {
                  x_opencti_organization_type
                  x_opencti_reliability
                }
                ... on Individual {
                  x_opencti_firstname
                  x_opencti_lastname
                }
              }
              ...Labels
              externalReferences {
                edges { node { url } }
              }
            }

            fragment IndShort on Indicator {
              id
              name
              valid_until
              revoked
              confidence
              x_opencti_score
              x_opencti_detection
              indicator_types
              x_mitre_platforms
              pattern_type
              pattern
              ...Labels
              killChainPhases { kill_chain_name }
            }

            fragment IndLong on Indicator {
              ...Object
              ...IndShort
            }

            fragment Indicators on StixCyberObservable {
              indicators { edges { node { ...IndShort } } }
            }

            fragment PageInfo on PageInfo {
              startCursor
              endCursor
              hasNextPage
              hasPreviousPage
              globalCount
            }

            fragment NameRelation on StixObjectOrStixRelationshipOrCreator {
              ... on DomainName { id value ...Indicators }
              ... on Hostname { id value ...Indicators }
            }

            fragment AddrRelation on StixObjectOrStixRelationshipOrCreator {
              ... on IPv4Addr { id value ...Indicators }
              ... on IPv6Addr { id value ...Indicators }
            }

            query IoCs($obs: FilterGroup, $ind: FilterGroup) {
              indicators(filters: $ind, first: 10) {
                edges { node { ...IndLong } }
                pageInfo { ...PageInfo }
              }
              stixCyberObservables(filters: $obs, first: 10) {
                edges {
                  node {
                    ...Object
                    observable_value
                    x_opencti_description
                    x_opencti_score
                    ...Indicators
                    ... on DomainName {
                      value
                      stixCoreRelationships(toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to { ...AddrRelation ...NameRelation }
                          }
                        }
                      }
                    }
                    ... on Hostname {
                      value
                      stixCoreRelationships(toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to { ...AddrRelation ...NameRelation }
                          }
                        }
                      }
                    }
                    ... on Url {
                      value
                      stixCoreRelationships(toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to { ...AddrRelation ...NameRelation }
                          }
                        }
                      }
                    }
                    ... on IPv4Addr {
                      value
                      stixCoreRelationships(fromTypes: ["Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: fromType
                            relationship_type
                            related: from { ...NameRelation }
                          }
                        }
                      }
                    }
                    ... on IPv6Addr {
                      value
                      stixCoreRelationships(fromTypes: ["Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: fromType
                            relationship_type
                            related: from { ...NameRelation }
                          }
                        }
                      }
                    }
                    ... on StixFile {
                      extensions
                      size
                      name
                      x_opencti_additional_names
                      hashes { algorithm hash }
                    }
                  }
                }
                pageInfo { ...PageInfo }
              }
            }
            ''',
            'variables': {
                'obs': {
                    "mode": "and",
                    "filterGroups": obs_filter_groups,
                    "filters": obs_filters
                },
                'ind': ind_var
            }
        }

        try:
            response = requests.post(url, headers=query_headers, json=api_json_body, timeout=20)
        except ConnectionError:
            log(f"Failed to connect to {url}")
            send_error_event("Failed to connect to the OpenCTI API", alert.get('agent'))
            continue

        try:
            response = response.json()
        except json.decoder.JSONDecodeError:
            log("# Failed to parse response from API")
            send_error_event("Failed to parse response from OpenCTI API", alert.get('agent'))
            continue

        debug("# Response:")
        debug(response)

        data = response.get('data')
        if not data:
            continue

        indicators_section = data.get('indicators', {})
        observables_section = data.get('stixCyberObservables', {})

        direct_indicators = []
        if ind_filter and indicators_section and 'edges' in indicators_section:
            direct_indicators = sorted(
                [x['node'] for x in indicators_section['edges']],
                key=indicator_sort_func
            )

            for indicator in direct_indicators[:max_ind_alerts]:
                new_alert = {
                    'integration': 'opencti',
                    'opencti': {
                        'indicator': modify_indicator(indicator),
                        'indicator_link': indicator_link(indicator),
                        'query_key': obs_key,
                        'query_values': ';'.join(ind_filter),
                        'event_type': (
                            'indicator_pattern_match'
                            if indicator.get('pattern') in ind_filter
                            else 'indicator_partial_pattern_match'
                        ),
                    }
                }
                add_context(alert, new_alert)
                new_alerts_all.append(remove_empties(new_alert))

        if not observables_section or 'edges' not in observables_section:
            continue

        direct_ids = [di['id'] for di in direct_indicators] if direct_indicators else []

        for edge in observables_section['edges'][:max_obs_alerts]:
            node = edge['node']

            ind_edges = node.get('indicators', {}).get('edges', [])
            indicators = sort_indicators([x['node'] for x in ind_edges]) if ind_edges else []

            related_obs_w_ind = relationship_with_indicators(node)

            if indicators:
                indicators = [i for i in indicators if i['id'] not in direct_ids]
            if related_obs_w_ind and related_obs_w_ind.get('indicator') and related_obs_w_ind['indicator']['id'] in direct_ids:
                related_obs_w_ind = None

            if not indicators and not related_obs_w_ind:
                new_alert = {'integration': 'opencti', 'opencti': node}
                new_alert['opencti']['related'] = None
                new_alert['opencti']['query_key'] = obs_key
                new_alert['opencti']['query_values'] = ';'.join(obs_values)
                new_alert['opencti']['event_type'] = 'observable_without_indicator'
                modify_observable(new_alert['opencti'], [])
                add_context(alert, new_alert)
                new_alerts_all.append(remove_empties(new_alert))
                continue

            new_alert = {'integration': 'opencti', 'opencti': node}
            new_alert['opencti']['related'] = related_obs_w_ind
            new_alert['opencti']['query_key'] = obs_key
            new_alert['opencti']['query_values'] = ';'.join(obs_values)
            new_alert['opencti']['event_type'] = (
                'observable_with_indicator' if indicators else 'observable_with_related_indicator'
            )

            modify_observable(new_alert['opencti'], indicators)
            add_context(alert, new_alert)
            new_alerts_all.append(remove_empties(new_alert))

    return new_alerts_all


if __name__ == '__main__':
    try:
        if len(sys.argv) < 4:
            log(f"Incorrect arguments: {' '.join(sys.argv)}")
            sys.exit(1)
        main(sys.argv)
    except Exception as e:
        debug(str(e), do_log=True)
        debug(traceback.format_exc(), do_log=True)
        raise
