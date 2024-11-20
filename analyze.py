import gzip
import zipfile
import os
import xml.etree.ElementTree as ET
import pandas as pd
import socket

def process_dmarc_report(file_path, data, spf_failures, dkim_failures):
    if file_path.endswith('.gz'):
        with gzip.open(file_path, 'rt') as f:
            tree = ET.parse(f)
            root = tree.getroot()
            extract_data(root, data, spf_failures, dkim_failures)
    elif file_path.endswith('.zip'):
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            for file in zip_ref.namelist():
                with zip_ref.open(file) as f:
                    tree = ET.parse(f)
                    root = tree.getroot()
                    extract_data(root, data, spf_failures, dkim_failures)

def extract_data(root, data, spf_failures, dkim_failures):
    for record in root.findall('.//record'):
        source_ip = record.find('row/source_ip').text
        disposition = record.find('row/policy_evaluated/disposition').text
        spf = record.find('row/policy_evaluated/spf').text
        dkim = record.find('row/policy_evaluated/dkim').text
        count = record.find('row/count').text
        
        data.append({
            'source_ip': source_ip,
            'disposition': disposition,
            'spf': spf,
            'dkim': dkim,
            'count': count
        })
        
        if spf == 'fail':  # Collect SPF failures
            spf_failures[source_ip] = spf_failures.get(source_ip, 0) + int(count)
        
        if dkim == 'fail':  # Collect DKIM failures
            dkim_failures[source_ip] = dkim_failures.get(source_ip, 0) + int(count)

def reverse_dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "No reverse DNS found"

def analyze_reports(directory):
    data = []  # List to hold the parsed data
    spf_failures = {}  # Dictionary to track SPF failures and their counts
    dkim_failures = {}  # Dictionary to track DKIM failures and their counts
    
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if filename.endswith('.xml.gz') or filename.endswith('.zip'):
            process_dmarc_report(file_path, data, spf_failures, dkim_failures)
    
    # Convert data to a DataFrame
    df = pd.DataFrame(data)
    
    # Save data to a CSV file or process it further
    df.to_csv('dmarc_report_analysis.csv', index=False)
    print("Analysis complete, saved to 'dmarc_report_analysis.csv'")

    # Output SPF and DKIM failures with reverse DNS
    print("\nSPF Failures (IP addresses and counts with reverse DNS):")
    for ip, count in spf_failures.items():
        reverse_dns = reverse_dns_lookup(ip)
        print(f"IP: {ip}, SPF Failures: {count}, Reverse DNS: {reverse_dns}")
    
    print("\nDKIM Failures (IP addresses and counts):")
    for ip, count in dkim_failures.items():
        print(f"IP: {ip}, DKIM Failures: {count}")
    
    return df

# Run the analysis
directory = './DMARC'
df = analyze_reports(directory)
