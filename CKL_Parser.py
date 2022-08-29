#!/usr/bin/env python3

# Imports
import xml.etree.ElementTree as ET
import os



#### CONTANT VARIABLES ####
# List of variables to pull from VULN tags
#   NOTE: Careful adding items, No checks for 'NONE' type returns
VULN_DATA = ['Vuln_Name', 'Severity', 'Group_Title', 'Rule_ID', 'Rule_Ver',
             'Rule_Title', 'Vuln_Discuss', 'Check_Content', 'Fix_Text',
             'STIGRef']


# Parses a ckl and returns root & Parse Tree
def parse_ckl(filename):
    try:
        pTree = ET.parse(filename)
        root = pTree.getroot()

        return root, pTree
    except:
        print(f'Unable to parse {filename}')


###
# Parse the ASSET section for Hostname, Host_IP, and Host_FQDN
###
def get_host_data(tree_root):
    host_data = {
        "hostname": tree_root.find('./ASSET/HOST_NAME').text,
        "host_ip": tree_root.find('./ASSET/HOST_IP').text,
        "host_fqdn": tree_root.find('./ASSET/HOST_FQDN').text
    }

    return host_data

###
# Parse STIG_INFO section to get informatio about specific STIG
###
def get_stig_info(tree_root):
    stig_dict = {}  #Empty Dictionary to be populated by STIG_INFO

    for si_data in tree_root.findall('./STIGS/iSTIG/STIG_INFO/SI_DATA'):
        sid_name = si_data.find('SID_NAME').text
        if si_data.find('SID_DATA') is not None:
            sid_data = si_data.find('SID_DATA').text
        else:
            sid_data = ""

        stig_dict[sid_name] = sid_data

    return stig_dict


###
# Get all vuln data and return in single dict
###
def get_vuln_data(tree_root):
    vuln_dict = {}
    for vuln in tree_root.findall('./STIGS/iSTIG/VULN'):
        # Pull Status, Finding_Details & Comments
        status = vuln.find('STATUS').text
        finding_details = vuln.find('FINDING_DETAILS').text
        comments = vuln.find('COMMENTS').text

        # Build out Vuln_Dict with all data
        vuln_dict = {
            "Status": status,
            "Finding Details": finding_details,
            "Comments": comments
        }

        # Parse through all K,V paired STIG_DATA
        for vuln_data in vuln.findall('STIG_DATA'):
            # Only save Vuln_data if in define VULN_DATA list
            if vuln_data.find('VULN_ATTRIBUTE').text in VULN_DATA:
                vuln_attr = vuln_data.find('VULN_ATTRIBUTE').text
                attr_data = vuln_data.find('ATTRIBUTE_DATA').text

                # Add if key exists, else create key
                if vuln_attr in vuln_dict.keys():
                    print(vuln_attr)
                    vuln_dict[vuln_attr] = vuln_dict[vuln_attr].append(attr_data)
                else:
                    vuln_dict[vuln_attr] = attr_data


    print(vuln_dict.get('Rule_ID'))
    return vuln_dict


if __name__ == '__main__':
    FILENAME = './CKLs/RHEL_7_STIG.ckl'
    root, pTree = parse_ckl(FILENAME)

    host_data = get_host_data(root)
    stig_info = get_stig_info(root)
    vuln_parsed = get_vuln_data(root)
