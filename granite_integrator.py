"""
Granite Integrator Module of DICE MNS
This module performs the following DICE-Granite Integration operations:
1. Queries Granite for a given Circuit ID
2. Parses and extracts the response data from Granite
3. Identifies DICE Market and DICE Device based on Granite information
4. Validates and cleans up the imported Granite data.

Author: Mohammed Abdul Khadeer
"""
import ast
import logging
import requests
import re
import socket
import struct
import ipaddress
from netaddr import IPNetwork
from difflib import SequenceMatcher
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from dice.models import Device, DeviceConfig, ServiceConfig, MarketStates, Tag
from dice.dice_mns.granite_field_mapping import BASE_ELEMENT_DICT, TARGET_DEVICE_DICT, TOPOLOGY_DICT
from dice.settings import DICE_GRANITE_URL

LOGGER = logging.getLogger('')


class GraniteIntegrator(object):
    """
    Queries Granite, parses response data, maps with corresponding DICE fields and validates mapped information.
    """

    def __init__(self, circuit_id, tag):
        self.circuit_id = circuit_id
        self.tag = tag

        self.response_data = {}
        self.element_data = {}
        self.granite_data = {}
        self.topology = {}

    def initiate(self):
        """
        Initiates the Granite Integration process by invoking corresponding modules in order
        :return:
        """
        # Step 1: Query Granite
        self.query_granite()

        # Step 2: Parse Response Data
        self.parse_response_data()

        # Step 3: Return Granite Data
        return self.granite_data

    def query_granite(self):
        """
        Queries Granite with Circuit ID and returns the raw response.
        :return:
        """
        granite_endpoint = DICE_GRANITE_URL + self.circuit_id

        response = requests.get(granite_endpoint, timeout=30, verify=False)

        self.response_data = response.json()

    def parse_response_data(self):
        """
        Parses through Granite response data and invokes extract and clean methods
        :return:
        """

        for element_dict in self.response_data['elements']:
            if 'status' in element_dict.keys() and element_dict['status']:
                status = element_dict['status']
                # Element data is parsed if and only if either a Circuit with same status (Live, Designed, etc)
                # has not been parsed before or the previous parsed circuit did not provide us a valid Market or Device.
                if status not in self.granite_data.keys() or \
                        (self.granite_data[status]['Market'] == '' or self.granite_data[status].get('Device',
                                                                                                    '') == ''):
                    self.element_data = {'Market': '', 'Device': ''}
                    self.topology = {}
                    try:
                        self.extract_element_data(element_dict)
                    except IndexError as err:
                        LOGGER.error(f"DICE MNS - Unable to find expected Sequence structure in "
                                     f"Granite's response for Circuit ID: {self.circuit_id}. Error: {err}")
                    except Exception as err:
                        LOGGER.error(f"DICE MNS - Unexpected error when extracting element data from "
                                     f"Granite response for Circuit ID: {self.circuit_id}. Error: {err}")

                    # self.get_device_type()
                    self.clean_element_data()
                    self.granite_data[status] = self.element_data

            else:
                LOGGER.info('DICE MNS - Status not available for element of Circuit ID: %s', self.circuit_id)

    def _get_topo_from_element(self, element_dict):
        # topology data
        for data in element_dict.get('data'):
            topo_type = data.get('topology')
            temp_topo = {}
            if topo_type == 'Point to Point':  # and device_role in ('C', 'Q', 'Z', 'A'):
                for dice_field, granite_field in TOPOLOGY_DICT.items():
                    try:
                        temp_topo[dice_field] = data[granite_field]
                    except KeyError:
                        LOGGER.info(
                            "DICE MNS - KeyError while importing Granite data for DICE topology field %s of Circuit ID: %s.",
                            dice_field,
                            self.circuit_id)

                if 'Device_role' in temp_topo and temp_topo['Device_role'] in self.topology:
                    if 'Port_ID' in self.topology[temp_topo['Device_role']]:
                        self.topology[temp_topo['Device_role']]['Port_ID'] = temp_topo['Port_ID']

                else:
                    self.topology[temp_topo['Device_role']] = temp_topo

        self._clean_topo_from_element()

    def _clean_topo_from_element(self):
        role_order = {
            'C': 'Upstream_Hub',
            'Q': 'QFX',
            'A': 'MTU',
            'Z': 'CPE'
        }

        clean_topo = {}
        for role, dice_role in role_order.items():
            device = self.topology.get(role)
            if device:
                if dice_role == 'Upstream_Hub':
                    # get lag name for lagged hub router.
                    if 'Leg_name' in device and device['Leg_name'] and '/AE' in device['Leg_name']:
                        device['Port_ID'] = device['Leg_name'].split()[0].split('/')[0]

                clean_topo[dice_role] = device

        self.topology = clean_topo

    def extract_element_data(self, element_dict):
        """
        Parses through Granite data and extracts required fields.
        :param: element_dict - dictionary containing element data
        :return:
        """

        # Getting the fields from the base element
        self._extract_data(BASE_ELEMENT_DICT, element_dict)

        # Getting the fields from the sequence of devices (element data)
        sequences = list(reversed(element_dict.get('data')))
        # Finding the index of the first CPE or MTU device (target device)
        seq_id = 0
        for i in range(len(sequences)):
            role = sequences[i].get('device_role')
            if role in ('Z', 'A'):
                seq_id = 1
                break

        # Extracting the data from the target device
        if int(sequences[seq_id]['sequence'].split('.')[-1]) > 1 \
                and sequences[seq_id].get('tid') == sequences[seq_id + 1].get('tid'):
            seq_id = seq_id + 1
        self._extract_data(TARGET_DEVICE_DICT, sequences[seq_id])

        # Handling the special case of ELAN VLAN and GLUE VLAN fields.
        # Initially, we assign "chan_name" field of the target device to ELAN VLAN and GLUE VLAN fields above based on
        # the field mapping. However, if the "chan_name" field is null, then we perform the following steps:
        # Step 1:   Check if "svlan" field is populated in the target device. If yes, we assign it to ELAN VLAN and
        #           GLUE VLAN fields. If not, then we proceed to step 2.
        # Step 2:   We traverse through the sequences from bottom-up until we hit the "device_role: Z" equipment.
        #           We check for both the "chan_name" and "svlan" fields. If either of them are populated, then
        #           we assign it to ELAN VLAN and GLUE VLAN fields. If not, we repeat the process until we exhaust
        #           all "device_role: Z" equipments. If we are unable to find a value in either "chan_name" or "svlan"
        #           fields for any "device_role: Z" equipments, then we proceed to step 3.
        # Step 3:   We traverse through the sequences from bottom-up until we hit the "device_role: C" equipment.
        #           We check for both the "chan_name" and "svlan" fields. If either of them are populated, then
        #           we assign it to ELAN VLAN and GLUE VLAN fields. If not, we repeat the process until we exhaust
        #           all "device_role: C" equipments. If we are unable to find a value in either "chan_name" or "svlan"
        #           fields for any "device_role: C" equipments, then we conclude our search for ELAN VLAN and GLUE VLAN.
        #
        # Note:     To simplify the implementation, we conduct the above steps for ELAN VLAN field and finally assign
        #           the value to GLUE VLAN field.
        if not self.element_data['ELAN VLAN']:
            # Step 1
            if sequences[seq_id]['svlan']:
                self.element_data['ELAN VLAN'] = sequences[seq_id]['svlan']
            else:
                c_seq_id = seq_id
                found_first_c_seq = False
                # Step 2
                for i in range(seq_id, len(sequences)):
                    sequence = sequences[i]
                    if sequence['device_role'] == 'Z':
                        if sequence['chan_name']:
                            self.element_data['ELAN VLAN'] = sequence['chan_name']
                            break
                        elif sequence['svlan']:
                            self.element_data['ELAN VLAN'] = sequence['svlan']
                            break
                    elif sequence['device_role'] == 'C' and not found_first_c_seq:
                        c_seq_id = i
                        found_first_c_seq = True

                if not self.element_data['ELAN VLAN']:
                    # Step 3
                    for i in range(c_seq_id, len(sequences)):
                        sequence = sequences[i]
                        if sequence['device_role'] == 'C':
                            if sequence['chan_name']:
                                self.element_data['ELAN VLAN'] = sequence['chan_name']
                                break
                            elif sequence['svlan']:
                                self.element_data['ELAN VLAN'] = sequence['svlan']
                                break

        self.element_data['GLUE VLAN'] = self.element_data['ELAN VLAN']

        self.element_data['Market'] = self.get_market(int(sequences[seq_id]['equip_zip_code']))
        self.element_data['Device'] = self.get_device(sequences[seq_id]['vendor'], sequences[seq_id]['model'])

        # grab topology data.
        self._get_topo_from_element(element_dict)
        self.element_data['topology'] = self.topology

    def _extract_data(self, field_map, data_sequence):
        """
        Extracts data based on fields in 'field_map' from Granite 'data_sequence'
        :param field_map: dictionary
        :param data_sequence: dictionary
        :return:
        """
        for dice_field, granite_field in field_map.items():
            try:
                self.element_data[dice_field] = data_sequence[granite_field]
            except KeyError:
                LOGGER.info("DICE MNS - KeyError while importing Granite data for DICE field %s of Circuit ID: %s.",
                            dice_field,
                            self.circuit_id)
            except Exception as error_message:
                LOGGER.info("DICE MNS - Error while importing Granite data for DICE field %s. "
                            "Error message: %s", dice_field, error_message)

    def get_market(self, zip_code):
        """
        Returns the corresponding Market for a given State
        :param zip_code: integer
        :return: market: string
        """
        market = ''
        try:
            market = MarketStates.objects.get(state=self.element_data['STATE']).market.name
        except (ObjectDoesNotExist, MultipleObjectsReturned):
            LOGGER.info("DICE MNS - No (unique) matching Market found for Zip Code %s associated with "
                        "Circuit ID: %s", zip_code, self.circuit_id)
        except Exception as error_message:
            LOGGER.error("DICE MNS - Unable to determine Market based on Granite data for Circuit ID: %s. "
                         "Error: %s", self.circuit_id, error_message)

        return market

    def get_device(self, vendor, model):
        """
        Returns the corresponding Device for a given Vendor and Model
        :param vendor: string
        :param model: string
        :return:
        """
        matched_device = ''
        try:
            # Removing trailing data and special characters from Granite 'model' field
            model = model.split('/')[0].replace('CC', '')
            model = re.sub('[^A-Za-z0-9]+', '', model)

            if model and vendor:
                matched_devices = {}

                # Step 1: Getting all vendor-specific devices from database
                vendor_devices = Device.objects.filter(name__istartswith=vendor, tag=self.tag)
                for device in vendor_devices:
                    # removing vendor prefix and special characters from device name
                    device_name = device.name.replace(vendor, '')
                    device_name = re.sub('[^A-Za-z0-9]+', '', device_name)

                    # Step 2: Comparing each device name with the Granite 'model' field
                    match = SequenceMatcher(None, model.lower(), device_name.lower()). \
                        find_longest_match(0, len(model), 0, len(device_name)).size

                    # Step 3: Storing {match percentage -> device name} in a dictionary
                    matched_devices[match * 100 / len(model)] = device.name

                if matched_devices:
                    # Step 4: Extracting the highest match percentage and assigning the associated device
                    # as matched device if the match percentage is greater than 90%
                    highest_match = max(k for k, v in matched_devices.items())
                    matched_device = matched_devices[highest_match]

        except Exception as error_message:
            LOGGER.error("DICE MNS - Error while identifying matched device using Granite info for Circuit ID: %s. "
                         "Error message: %s", self.circuit_id, error_message)

        return matched_device

    def clean_element_data(self):
        """
        Validates and cleans up the imported Granite data by comparing it with available options in DICE
        Removes any fields that don't match the default data for a DeviceConfig
        :return:
        """
        device = self.element_data['Device']
        if device:
            try:
                dev_obj = Device.objects.get(name=device, tag=self.tag)
                device_config = DeviceConfig.objects.get(device=dev_obj)
                default_values = ast.literal_eval(device_config.default_values)
                service_configs = ServiceConfig.objects.filter(device=dev_obj)

                for service_config in service_configs:
                    default_values += ast.literal_eval(service_config.default_values)

                for def_val in default_values:
                    if isinstance(def_val['values'], list) and def_val['fields'] in self.element_data.keys():
                        actual_val = self.element_data[def_val['fields']]
                        # Sometimes we may have to split ports on the slash
                        if actual_val and actual_val not in def_val['values']:
                            actual_val = actual_val.split('/')[-1]
                            if actual_val not in def_val['values']:
                                actual_val = actual_val.split()[-1]
                                if actual_val not in def_val['values']:
                                    self.element_data[def_val['fields']] = None
                                else:
                                    self.element_data[def_val['fields']] = actual_val
                            else:
                                self.element_data[def_val['fields']] = actual_val

            except (ObjectDoesNotExist, MultipleObjectsReturned):
                LOGGER.info("DICE MNS - No (unique) Device and/or DeviceConfig objects found for the Device Name %s "
                            "extracted from Granite for Circuit ID: %s", device, self.circuit_id)

            except Exception as error_message:
                LOGGER.error("DICE MNS - Error while comparing Granite data with available options "
                             "for multi-value fields for Circuit ID: %s. Error: %s", self.circuit_id, error_message)

        # Converting WAN CIR value extracted from Granite and adding new elements to
        # element_data dictionary based on WAN CIR variables of each Service
        self.element_data['WAN CIR'] = self.element_data['WAN CIR'].replace('bps', '').replace(' ', '')
        all_service_configs = ServiceConfig.objects.filter(service__tag=self.tag)
        for service_config in all_service_configs:
            input_variables = ast.literal_eval(service_config.input_variables)
            for inp_var in input_variables:
                if re.match('(WAN CIR.+?)', inp_var):
                    self.element_data[inp_var] = self.element_data['WAN CIR']

        # Extracting GLUE IP and GLUE Mask from ip4_address value
        if 'GLUE IP' in self.element_data and self.element_data['GLUE IP']:
            self.element_data['GLUE IP'], self.element_data['GLUE MASK'] = \
                self.calculate_ip_and_netmask(self.element_data['GLUE IP'])

        # Extracting CML IP and CML Mask from ems_ip_address value
        if 'CML IP' in self.element_data and self.element_data['CML IP']:
            # Calculating CML GW using CML IP Value
            self.element_data['CML GW'] = str(IPNetwork(self.element_data['CML IP'])[1])

            self.element_data['CML IP'], self.element_data['CML MASK'] = \
                self.calculate_ip_and_netmask(self.element_data['CML IP'])

        # calculate ELAN NW off of ELAN IP
        if 'ELAN IP' in self.element_data and self.element_data['ELAN IP']:
            ips = self.element_data['ELAN IP'].strip().split(',')
            self.element_data['ELAN NW'] = ', '.join([str(ipaddress.IPv4Network(ip.replace(' ', ''), strict=False).
                                                          network_address) for ip in ips])

        # Extracting ELAN IP and ELAN Mask from secondary_access_device_ip value
        if 'ELAN IP' in self.element_data and self.element_data['ELAN IP']:
            self.element_data['ELAN IP'], self.element_data['ELAN MASK'] = \
                self.calculate_ip_and_netmask(self.element_data['ELAN IP'])

            # checking CML IP, if empty or doesnt exist, inheriting from ELAN IP. 
            if 'CML IP' not in self.element_data or not self.element_data['CML IP']:
                self.element_data['CML IP'] = self.element_data['ELAN IP']

        # Extracting Routed Handoff IP and Routed Handoff Mask from secondary_access_device_ip value.
        # If multiple values exist, then extract Secondary Routed Handoff IP and Secondary Routed Handoff Mask.
        if 'Routed Handoff IP' in self.element_data and self.element_data['Routed Handoff IP']:
            routed_handoff_ips = self.element_data['ELAN IP'].strip().split(',')
            if len(routed_handoff_ips) == 2:
                self.element_data['Routed Handoff IP'] = routed_handoff_ips[0]
                self.element_data['Secondary Routed Handoff IP'] = routed_handoff_ips[1]

                self.element_data['Secondary Routed Handoff IP'], self.element_data['Secondary Routed Handoff Mask'] = \
                    self.calculate_ip_and_netmask(self.element_data['Secondary Routed Handoff IP'])

            self.element_data['Routed Handoff IP'], self.element_data['Routed Handoff Mask'] = \
                self.calculate_ip_and_netmask(self.element_data['Routed Handoff IP'])

        # Removing trailing netmask bits from OSPF ROUTER ID
        if 'OSPF ROUTER ID' in self.element_data and self.element_data['OSPF ROUTER ID']:
            self.element_data['OSPF ROUTER ID'] = self.element_data['OSPF ROUTER ID'].split('/')[0].strip()

        # stripping ALPHA from any VLAN value
        vlan_keys = ['GLUE VLAN', 'ELAN VLAN']
        for key in vlan_keys:
            if key in self.element_data and self.element_data[key]:
                self.element_data[key] = re.sub("[^0-9]", "", self.element_data[key])

        # calculate ELAN WILDCARD MASK by inversing ELAN MASK
        if 'ELAN MASK' in self.element_data and self.element_data['ELAN MASK']:
            self.element_data['ELAN WILDCARD MASK'] = '.'.join(
                [str(255 - int(i)) for i in self.element_data['ELAN MASK'].split('.')])

        # fix data specific to ELAN circuits. 
        if 'SERVICE' in self.element_data and self.element_data['SERVICE'] and "EPLAN" in self.element_data['SERVICE']:
            # ensure OSPF ROUTER ID inherits from CML IP
            self.element_data['OSPF ROUTER ID'] = self.element_data.get('CML IP')

        # fix FQDN if coming in blank
        if 'FQDN' in self.element_data and not self.element_data['FQDN'] or 'FQDN' not in self.element_data:
            self.element_data[
                'FQDN'] = f"{self.element_data['Hostname']}.CHTRSE.COM" if 'Hostname' in self.element_data else 'Invalid FQDN'

        # clearing all None values.
        self.element_data = {field: value for field, value in self.element_data.items() if value}

    def calculate_ip_and_netmask(self, cidr):
        """
        Calculates IP and Net Mask for a given CIDR
        :return:
        """
        ip = cidr
        netmask = ''
        ip_and_bits = cidr.split('/')
        if len(ip_and_bits) == 2 and len(ip_and_bits[1]) == 2:
            ip = ip_and_bits[0].strip()
            bits = ip_and_bits[1].strip()
            netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << (32 - int(bits)))))

        return ip, netmask


if __name__ == "__main__":
    (tag_obj, is_created) = Tag.objects.get_or_create(name='managed')

    print("FIAs ~ ~ ~ ~ ~ ~ ~ ~ ~ ~")
    GraniteIntegrator('32.L1XX.805216..TWCC', tag_obj).initiate()
    GraniteIntegrator('71.L1XX.009718..TWCC', tag_obj).initiate()
    GraniteIntegrator('32.L1XX.805228..TWCC', tag_obj).initiate()
    GraniteIntegrator('62.L1XX.004967..TWCC', tag_obj).initiate()
    GraniteIntegrator('90.L1XX.800617..TWCC', tag_obj).initiate()
    GraniteIntegrator('81.L1XX.907517..TWCC', tag_obj).initiate()
    GraniteIntegrator('81.L1XX.907518..TWCC', tag_obj).initiate()
    GraniteIntegrator('71.L1XX.009731..TWCC', tag_obj).initiate()
    GraniteIntegrator('81.L1XX.881520..TWCC', tag_obj).initiate()
    GraniteIntegrator('32.L1XX.805215..TWCC', tag_obj).initiate()

    print("\n\n")

    print("ELANs ~ ~ ~ ~ ~ ~ ~ ~ ~ ~")
    GraniteIntegrator('32.L1XX.105567..TWCC', tag_obj).initiate()
    GraniteIntegrator('65.L1XX.000205..TWCC', tag_obj).initiate()
    GraniteIntegrator('32.L1XX.105565..TWCC', tag_obj).initiate()
    GraniteIntegrator('62.L1XX.004796..TWCC', tag_obj).initiate()
    GraniteIntegrator('90.L1XX.800360..TWCC', tag_obj).initiate()
    GraniteIntegrator('81.L1XX.808348..TWCC', tag_obj).initiate()
    GraniteIntegrator('81.L1XX.808347..TWCC', tag_obj).initiate()
    GraniteIntegrator('71.L1XX.008787..TWCC', tag_obj).initiate()
    GraniteIntegrator('81.L1XX.881507..TWCC', tag_obj).initiate()
    GraniteIntegrator('56.L1XX.345925..TWCC', tag_obj).initiate()

    print("\n\n")

    print("C1111 ~ ~ ~ ~ ~ ~ ~ ~ ~ ~")
    GraniteIntegrator('92.L1XX.000019.218.TWCC', tag_obj).initiate()
