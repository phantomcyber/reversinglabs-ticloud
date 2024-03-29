# --
#
# Copyright (c) ReversingLabs Inc 2016-2019
#
# This unpublished material is proprietary to ReversingLabs Inc.
# All rights reserved.
# Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of ReversingLabs Inc.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult

# THIS Connector imports
from reversinglabs_consts import *

# Other imports used by this connector
import simplejson as json
import hashlib
import requests
from requests.auth import HTTPBasicAuth
from collections import defaultdict


class ReversinglabsConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_QUERY_FILE = "lookup_file"

    def __init__(self):

        # Call the BaseConnectors init first
        super(ReversinglabsConnector, self).__init__()

        self._malicious_status = ["MALICIOUS", "SUSPICIOUS"]
        self._headers = {'content-type': 'application/octet-stream'}
        self._auth = None
        self._mwp_url = MAL_PRESENCE_API_URL
        self._xref_url = XREF_API_URL
        self._verify_cert = True

    def initialize(self):

        config = self.get_config()
        # setup the auth
        self._auth = HTTPBasicAuth(phantom.get_req_value(config, phantom.APP_JSON_USERNAME),
                phantom.get_req_value(config, phantom.APP_JSON_PASSWORD))

        if "url" in config:
            self._mwp_url = "{0}{1}".format(config["url"], MAL_PRESENCE_API_URL_ENDPOINT)
            self._xref_url = "{0}{1}".format(config["url"], XREF_API_URL_ENDPOINT)

        if "verify_server_cert" in config:
            self._verify_cert = config["verify_server_cert"]

        self.debug_print('self.status', self.get_status())

        return phantom.APP_SUCCESS

    def _test_asset_connectivity(self, param):

        # Create a hash of a random string
        random_string = phantom.get_random_chars(size=10)

        md5_hash = hashlib.md5(random_string).hexdigest()

        self.save_progress(REVERSINGLABS_GENERATED_RANDOM_HASH)

        tree = lambda: defaultdict(tree)  # noqa: E731, E261
        hash_type = 'md5'
        query = tree()
        query['rl']['query']['hash_type'] = hash_type
        query['rl']['query']['hashes'] = [md5_hash]

        try:
            r = requests.post(self._mwp_url, auth=self._auth, data=json.dumps(query), headers=self._headers, verify=self._verify_cert)
        except Exception as e:
            self.set_status(phantom.APP_ERROR, 'Request to server failed', e)
            self.save_progress(REVERSINGLABS_SUCC_CONNECTIVITY_TEST)
            return self.get_status()

        if (r.status_code != 200):
            self.set_status(phantom.APP_ERROR)
            status_message = '{0}. {1}. HTTP status_code: {2}, reason: {3}'.format(REVERSINGLABS_ERR_CONNECTIVITY_TEST,
                REVERSINGLABS_MSG_CHECK_CREDENTIALS, r.status_code, r.reason)
            self.append_to_message(status_message)
            self.append_to_message(self._mwp_url)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, REVERSINGLABS_SUCC_CONNECTIVITY_TEST)

    def _handle_samples(self, action_result, samples):

        if (not samples):
            return

        for sample in samples:

            if (not sample):
                continue

            try:
                # Get the data dictionary into the result to store information
                hash_data = action_result.get_data()[0]
            except:
                continue

            # Update the data with what we got
            hash_data.update(sample)
            print "_handle_samples: " + str(sample) + "\n ----------------------------------------------"
            try:
                positives = sample['xref'][0]['scanner_match']
                # Update the summary
                action_result.update_summary({REVERSINGLABS_JSON_TOTAL_SCANS: sample['xref'][0]['scanner_count'],
                    REVERSINGLABS_JSON_POSITIVES: positives})
            except:
                continue

        return

    def _get_hash_type(self, hash_to_query):

        if (phantom.is_md5(hash_to_query)):
            return 'md5'

        if (phantom.is_sha1(hash_to_query)):
            return 'sha1'

        if (phantom.is_sha256(hash_to_query)):
            return 'sha256'

        return None

    def _query_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # get the hash
        hash_to_query = param[phantom.APP_JSON_HASH]

        # get the hash type
        hash_type = self._get_hash_type(hash_to_query)

        if (not hash_type):
            return action_result.set_status(phantom.APP_ERROR, "Unable to detect Hash Type")

        tree = lambda: defaultdict(tree)  # noqa: E731, E261

        query = tree()
        query['rl']['query']['hash_type'] = hash_type
        query['rl']['query']['hashes'] = [hash_to_query]

        # First the malware presence
        self.save_progress(REVERSINGLABS_MSG_CONNECTING_WITH_URL)

        try:
            r = requests.post(self._mwp_url, auth=self._auth, data=json.dumps(query), headers=self._headers, verify=self._verify_cert)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Request to server failed", e)

        if (r.status_code != 200):
            return action_result.set_status(phantom.APP_ERROR, REVERSINGLABS_ERR_MALWARE_PRESENCE_QUERY_FAILED, ret_code=r.status_code, ret_reason=r.reason)

        try:
            rl_result = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Response does not seem to be a valid JSON", e)

        # set the status to success
        action_result.set_status(phantom.APP_SUCCESS)

        entries = rl_result.get('rl', {}).get('entries')

        if (not entries):
            return action_result.set_status(phantom.APP_ERROR, "Response does contains empty or None 'entries'")

        # Queried for a hash, so it should be present in the return value
        entry = entries[0]

        # Add a data dictionary into the result to store information
        hash_data = action_result.add_data({'mwp_result': entry})

        # Add the status into it
        hash_data[REVERSINGLABS_JSON_STATUS] = entry.get('status', 'Unknown')

        # Set the summary
        action_result.update_summary({REVERSINGLABS_JSON_TOTAL_SCANS: 0, REVERSINGLABS_JSON_POSITIVES: 0})

        if (hash_data[REVERSINGLABS_JSON_STATUS] not in self._malicious_status):
            # No need to do anything more for this hash
            return action_result.set_status(phantom.APP_SUCCESS)

        self.save_progress(REVERSINGLABS_MSG_CONNECTING_WITH_URL)

        try:
            r = requests.post(self._xref_url, auth=self._auth, data=json.dumps(query), headers=self._headers, verify=self._verify_cert)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "XREF API Request to server failed", e)

        if (r.status_code != 200):
            self.debug_print("status code", r.status_code)
            return action_result.set_status(phantom.APP_ERROR, "XREF API Request to server error: {0}".format(r.status_code))

        try:
            rl_result = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "XREF Response does not seem to be a valid JSON", e)

        action_result.add_debug_data(rl_result)
        action_result.add_debug_data({'mwp_result': entry})
        samples = rl_result.get('rl', {}).get('samples')
        samples.append(entry)
        if (not samples):
            return action_result.set_status(phantom.APP_ERROR, "Response contains empty or none 'samples'")
        self._handle_samples(action_result, samples)

        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if (action == self.ACTION_ID_QUERY_FILE):
            result = self._query_file(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_asset_connectivity(param)

        return result

    def finalize(self):

        # Init the positives
        total_positives = 0

        # Loop through the action results that we had added before
        for action_result in self.get_action_results():
            action = self.get_action_identifier()
            if (action == self.ACTION_ID_QUERY_FILE):
                # get the summary of the current one
                summary = action_result.get_summary()

                if (REVERSINGLABS_JSON_POSITIVES not in summary):
                    continue

                # If the detection is true
                if (summary[REVERSINGLABS_JSON_POSITIVES] > 0):
                    total_positives += 1

                self.update_summary({REVERSINGLABS_JSON_TOTAL_POSITIVES: total_positives})


if __name__ == '__main__':

    import sys
    # import pudb
    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = ReversinglabsConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print ret_val

    exit(0)
