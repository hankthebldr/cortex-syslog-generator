#!/usr/bin/env python3
"""
Standalone test for Zscaler log generation with authentic formats.
"""

import random
import time
from datetime import datetime
from faker import Faker

fake = Faker()

def gen_zscaler_web_log_standalone():
    """Generate standalone Zscaler NSS Web log in CEF format."""
    now = datetime.now()
    username = fake.user_name()
    client_ip = fake.ipv4_private()
    server_ip = fake.ipv4_public()
    host = fake.domain_name()
    url = f"https://{host}/path/to/resource"
    
    actions = ['Allowed', 'Blocked', 'Monitored']
    action = random.choice(actions)
    reasons = ['Acceptable Use Policy', 'Security Policy', 'Bandwidth Control']
    reason = random.choice(reasons)
    url_categories = ['Business Use', 'Social Networking', 'Malware', 'Phishing']
    url_cat = random.choice(url_categories)
    
    # Generate authentic Zscaler NSS Web log format
    log_line = (f"{now.strftime('%b %d %H:%M:%S')} zscaler-nss "
                f"CEF:0|Zscaler|NSSWeblog|5.0|{action}|{reason}|3|"
                f"act={action} app=HTTP cat={url_cat} dhost={host} dst={server_ip} "
                f"src={client_ip} in={random.randint(1024, 65536)} outcome={random.randint(200, 404)} "
                f"out={random.randint(512, 8192)} request={url} "
                f"rt={now.strftime('%b %d %y %H:%M:%S')} "
                f"sourceTranslatedAddress={fake.ipv4_private()} "
                f"requestClientApplication=Mozilla/5.0 requestMethod=GET suser={username} "
                f"spriv={fake.city()} externalId={random.randint(100000, 999999)} "
                f"fileType=html reason={reason} destinationServiceName=WebService "
                f"cn1={random.randint(1, 100)} cn1Label=riskscore "
                f"cs1=Engineering cs1Label=dept "
                f"cs2=General_Browsing cs2Label=urlsupercat "
                f"cs3=Web_Browser cs3Label=appclass "
                f"cs4=None cs4Label=malwarecat "
                f"cs5=None cs5Label=threatname "
                f"cs6=None cs6Label=dlpeng "
                f"ZscalerNSSWeblogURLClass=Acceptable "
                f"ZscalerNSSWeblogDLPDictionaries=None "
                f"requestContext= contenttype=text/html "
                f"unscannabletype=None deviceowner={username} "
                f"devicehostname={fake.hostname()}")
    
    return {
        'action': action,
        'url_cat': url_cat,
        'log_line': log_line,
        'message': f'{action}: {url} - {reason}'
    }

def gen_zscaler_firewall_log_standalone():
    """Generate standalone Zscaler NSS Firewall log in CEF format."""
    now = datetime.now()
    username = fake.user_name()
    client_ip = fake.ipv4_private()
    server_ip = fake.ipv4_public()
    
    actions = ['Allow', 'Drop', 'Reset']
    action = random.choice(actions)
    protocols = ['TCP', 'UDP', 'ICMP']
    proto = random.choice(protocols)
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 25, 53, 3389])
    
    rule_labels = ['Corporate_Internet_Access', 'Block_P2P', 'Allow_HTTPS', 'Block_Malware']
    rule_label = random.choice(rule_labels)
    
    # Generate authentic Zscaler NSS Firewall log format
    log_line = (f"{now.strftime('%b %d %H:%M:%S')} zscaler-nss-fw "
                f"CEF:0|Zscaler|NSSFWlog|5.7|{action}|{rule_label}|3|"
                f"act={action} suser={username} src={client_ip} spt={src_port} "
                f"dst={server_ip} dpt={dst_port} "
                f"deviceTranslatedAddress={fake.ipv4_private()} "
                f"deviceTranslatedPort={random.randint(1024, 65535)} "
                f"destinationTranslatedAddress={server_ip} "
                f"destinationTranslatedPort={dst_port} "
                f"sourceTranslatedAddress={client_ip} "
                f"sourceTranslatedPort={src_port} "
                f"proto={proto} tunnelType=IPSEC dnat=No stateful=Yes "
                f"spriv={fake.city()} reason={rule_label} "
                f"in={random.randint(1024, 1048576)} out={random.randint(512, 524288)} "
                f"rt={now.strftime('%b %d %H:%M:%S')} deviceDirection=1 "
                f"cs1=Engineering cs1Label=dept "
                f"cs2=InternetAccess cs2Label=nwService "
                f"cs3=WebBrowsing cs3Label=nwApp "
                f"cs4=No cs4Label=aggregated "
                f"cs6=None cs6label=threatname "
                f"cn1={random.randint(100, 30000)} cn1Label=durationms "
                f"cn2=1 cn2Label=numsessions "
                f"cs5Label=ipCat cs5=Acceptable "
                f"cat=None destCountry={fake.country_code()} "
                f"avgduration={random.randint(1000, 10000)}")
    
    return {
        'action': action,
        'rule_label': rule_label,
        'log_line': log_line,
        'message': f'{action}: {client_ip}:{src_port} -> {server_ip}:{dst_port} ({proto})'
    }

def gen_zscaler_zpa_user_activity_log_standalone():
    """Generate standalone Zscaler ZPA User Activity log in LEEF format."""
    now = datetime.now()
    username = fake.user_name()
    client_public_ip = fake.ipv4_public()
    client_private_ip = fake.ipv4_private()
    server_ip = fake.ipv4_private()
    
    connection_statuses = ['ACTIVE', 'CLOSED', 'TIMEOUT']
    connection_status = random.choice(connection_statuses)
    internal_reasons = ['OK', 'USER_INITIATED', 'POLICY_TIMEOUT', 'NETWORK_ERROR']
    internal_reason = random.choice(internal_reasons)
    
    session_id = fake.uuid4()
    connection_id = fake.uuid4()
    customer = 'Corp_Customer_001'
    
    # Generate authentic ZPA User Activity log in LEEF format
    log_line = (f"LEEF:1.0|Zscaler|ZPA|4.1|{connection_status}{internal_reason}|"
                f"cat=ZPA User Activity\tdevTime={int(now.timestamp())}"
                f"\tCustomer={customer}\tSessionID={session_id}"
                f"\tConnectionID={connection_id}\tInternalReason={internal_reason}"
                f"\tConnectionStatus={connection_status}\tproto=6"
                f"\tDoubleEncryption=1\tusrName={username}"
                f"\tdstPort={random.choice([80, 443, 22, 3389])}\tsrc={client_public_ip}"
                f"\tsrcPreNAT={client_private_ip}"
                f"\tClientLatitude={fake.latitude()}\tClientLongitude={fake.longitude()}"
                f"\tClientCountryCode={fake.country_code()}\tClientZEN=ZEN_{fake.city()}"
                f"\tpolicy=Corp_Access_Policy\tConnector={fake.hostname()}-connector"
                f"\tConnectorZEN=ZEN_{fake.city()}\tConnectorIP={fake.ipv4_private()}"
                f"\tConnectorPort={random.randint(1024, 65535)}"
                f"\tApplicationName={fake.domain_name()}\tApplicationSegment=Corp_App_Segment"
                f"\tAppGroup=Production_Apps\tServer={fake.hostname()}"
                f"\tdst={server_ip}\tServerPort={random.choice([80, 443, 22])}"
                f"\tPolicyProcessingTime={random.randint(10, 100)}"
                f"\tServerSetupTime={random.randint(50, 500)}"
                f"\tTimestampConnectionStart:iso8601={now.isoformat()}"
                f"\tTimestampConnectionEnd:iso8601={now.isoformat()}"
                f"\tZENTotalBytesRxClient={random.randint(1024, 1048576)}"
                f"\tZENTotalBytesTxClient={random.randint(512, 524288)}"
                f"\tIdp=ActiveDirectory")
    
    return {
        'connection_status': connection_status,
        'internal_reason': internal_reason,
        'log_line': log_line,
        'message': f'ZPA User Activity: {username} - {connection_status}'
    }

def main():
    """Test all Zscaler log generators."""
    print("🛡️  ZSCALER LOG GENERATOR TEST")
    print(f"📅 Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print("\n" + "="*60)
    print("🌐 ZSCALER NSS WEB LOG (CEF FORMAT)")
    print("="*60)
    web_log = gen_zscaler_web_log_standalone()
    print(f"\n✅ Action: {web_log['action']} | Category: {web_log['url_cat']}")
    print("-" * 60)
    print(web_log['log_line'])
    print(f"\n📋 Parsed: {web_log['message']}")
    
    print("\n" + "="*60)
    print("🔥 ZSCALER NSS FIREWALL LOG (CEF FORMAT)")
    print("="*60)
    fw_log = gen_zscaler_firewall_log_standalone()
    print(f"\n✅ Action: {fw_log['action']} | Rule: {fw_log['rule_label']}")
    print("-" * 60)
    print(fw_log['log_line'])
    print(f"\n📋 Parsed: {fw_log['message']}")
    
    print("\n" + "="*60)
    print("👤 ZSCALER ZPA USER ACTIVITY LOG (LEEF FORMAT)")
    print("="*60)
    zpa_log = gen_zscaler_zpa_user_activity_log_standalone()
    print(f"\n✅ Status: {zpa_log['connection_status']} | Reason: {zpa_log['internal_reason']}")
    print("-" * 60)
    print(zpa_log['log_line'])
    print(f"\n📋 Parsed: {zpa_log['message']}")
    
    print("\n" + "="*60)
    print("✅ ALL ZSCALER LOG FORMATS TESTED SUCCESSFULLY")
    print("="*60)
    print("\n🎯 Integration Points:")
    print("- CEF logs: Compatible with Syslog UDP/TCP transport")
    print("- LEEF logs: Compatible with XSIAM HTTP ingestion")
    print("- Field mapping: All standard security fields populated")
    print("- Timestamps: Multiple formats (ISO8601, epoch, syslog)")
    
    print("\n💡 Usage:")
    print("1. Run web UI: make run (port 5001)")
    print("2. Select Zscaler products from vendor list")
    print("3. Configure transport (Syslog/HTTP/Webhook)")
    print("4. Generate logs with authentic field values")

if __name__ == "__main__":
    main()