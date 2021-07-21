BASE_ELEMENT_DICT = {
    "WAN CIR": "bandwidth",
    "SERVICE": "service_type"
}

TARGET_DEVICE_DICT = {
    "Hostname": "tid",
    "ADDRESS": "full_address",
    "STATE": "equip_state",
    "ELAN VLAN": "chan_name",
    "GLUE VLAN": "chan_name",
    "OSPF ROUTER ID": "management_ip",
    "GLUE IP": "management_ip",
    "GLUE GW": "gne_ip_address",
    "CML IP": "ems_ip_address",
    "ELAN IP": "secondary_access_device_ip",
    "Routed Handoff IP": "secondary_access_device_ip",
    "Vendor": "vendor",
    "Model": "model",
    "FQDN": "device_id"
}


TOPOLOGY_DICT = {
    'Topology_type': 'topology',
    'Device_role': 'device_role',
    'TID': 'tid',
    'Leg_name': 'leg_name',
    'MGMT_IP': 'management_ip',
    'Port_ID': 'port_access_id'
}
