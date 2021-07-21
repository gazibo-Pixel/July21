"""
sense MNS Module of DICE MNS
This module performs the following DICE-> SENSE operations:
1. intakes data from DICE
2. compiles datamodel for sense api call.
3. makes API call
4. returns resource ID recieved from sense.
    - can also retreive status update from sense if resource ID is provided.

Author: Sydney Andrade
"""
import logging
import requests
import json
from cryptography.fernet import Fernet
from dice.settings import MNS_PATHS
from seek.settings import API_ENDPOINT, API_MDSO_CALL_TIMEOUT

LOGGER = logging.getLogger('')

def get_cred(cred):
    data = cred.split('::')
    fern = Fernet(data[1].encode())
    return fern.decrypt(data[0].encode()).decode()



class ManagedAutomator:
    """
    makes post to SENSE/managed_services endpoint to initiate automated provisioning.
    """
    MNS_ENDPOINT = f"{API_ENDPOINT}/{MNS_PATHS['mns_post']}"
    STATUS_ENDPOINT = f"{API_ENDPOINT}/{MNS_PATHS['mns_status']}"

    CREDS = {
        'username': get_cred(MNS_PATHS['mns_sense_creds']['username']),
        'password': get_cred(MNS_PATHS['mns_sense_creds']['password'])
    }
    
    SCHEMA = {
        'ipAddress': str,
        'vendor': str,
        'model': str,
        'fqdn': str,
        'configuration': list
    }

    def __init__(self, ipAddress=None, vendor=None, model=None, fqdn=None, config=None):
        self.ipAddress = ipAddress
        self.vendor = vendor
        self.model = model
        self.fqdn = fqdn
        self.resource_id = ''

        if config: 
            if isinstance(config, str):
                self.raw_config = config 
            elif isinstance(config, list):
                try:
                    self.raw_config = '\n'.join(config)
                except TypeError:
                    self.raw_config = 'bad config provided'
            else:
                self.raw_config = 'bad config provided'
        else:
            self.raw_config = 'bad config provided'
        
    @property
    def config(self):
        """
        property that converts raw_config to proper config list that can be sent to sense.
        """
        if self.raw_config == 'bad config provided':
            return self.raw_config
        else:
            return self.raw_config.split('\n')

    @property
    def payload(self):
        """
        property that converts instance data to proper payload that can be sent to sense.
        """
        return {
            "ipAddress": self.ipAddress,
            "vendor": self.vendor,
            "model": self.model,
            "fqdn": self.fqdn,
            "configuration": self.config
            }

    @payload.setter
    def payload(self, payload):
        """
        property setter that will overwrite the attributes created upon instantiation.
        can be used as an alternative to paramters in __init__
        """
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key == 'configuration':
                    if isinstance(value, list):
                        self.raw_config = '\n'.join(value)
                    elif isinstance(value, str):
                        self.raw_config = value
                    else:
                        self.raw_config = 'bad config provided'
                elif hasattr(self, key):
                    setattr(self, key, value) 
        else:
            raise TypeError("payload must be set in form of python dictionary")

    @property
    def is_payload_valid(self):
        """
        returns a True or False depending on validity of payload.
        just checks if data of of specific type.
        """
        for k, v in self.payload.items():
            try:
                if not isinstance(v, self.SCHEMA[k]):
                    return False
            except KeyError:
                return False
        return True

    def automate(self, force_reattempt=False):
        """
        makes call to sense managed_service endpoint with proper payload. after confirming payload is correct.
        :return:
        """
        if not self.resource_id or force_reattempt:
            if self.is_payload_valid:
                response = requests.post(ManagedAutomator.MNS_ENDPOINT, timeout=API_MDSO_CALL_TIMEOUT, 
                                        verify=False, data=json.dumps(self.payload), auth=(self.CREDS['username'], self.CREDS['password']))
            
                try:
                    self.resource_id = response.json()['resource_id']
                except KeyError:
                    pass

                return response

            else:
                raise Exception("Payload invalid for sense managed_service POST. Please correct payload issues before retrying")
        else:
            raise Exception("Appears automation for this payload has already been attempted. Please do not reattempt")

    def status(self):
        """
        checks status of resource ID of instance.
        :return:
        """
        if hasattr(self, 'resource_id'):
            return self.check_status(self.resource_id)
        else:
            raise Exception("Appears automation for this payload has not yet been attempted")

    @staticmethod
    def check_status(resource_id):
        """
        checks status of any provided resource id without having to create an instance.
        :return:
        """
        response = requests.get(f'{ManagedAutomator.STATUS_ENDPOINT}?resourceId={resource_id}', timeout=API_MDSO_CALL_TIMEOUT, verify=False)
                
        return response


def test():
    ma = ManagedAutomator('192.168.1.1', 'cisco', 'c-1111', 'AUSTDXIR1ZW.DEV.CHTRSE.COM')
    print(ma.payload)
    assert ma.is_payload_valid == False
    ma.payload = {'config': 'line1\nline2\nline3'}
    print(ma.payload)
    assert ma.is_payload_valid == True
    print(ma.config)

    try:
        ma.status()
    except Exception as e:
        print(e)

    # below will make outbound calls to apis
    ma.automate()
    ma.status()

    try:
        ma.automate()
    except Exception as e:
        print(e)

    ma.automate(force_reattempt=True)
    print("tests complete")

    print(ManagedAutomator.MNS_ENDPOINT)
    print(ManagedAutomator.STATUS_ENDPOINT)


if __name__ == '__main__':
    test()