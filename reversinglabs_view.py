# --
#
# Copyright (c) ReversingLabs Inc 2016-2018
#
# This unpublished material is proprietary to ReversingLabs Inc.
# All rights reserved.
# Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of ReversingLabs Inc.
#
# --

from reversinglabs_consts import *
from phantom.json_keys import *


def file_reputation(provides, all_results, context):

    tally = {'total_positives': 0,
            'total_found': 0,
            'total_queried': 0}

    results = []
    parameters = {}
    for summary, action_results in all_results:
        # print "summary " + str(summary) + " action_results " + str(action_results)
        if not summary or not action_results:
            continue
        tally['total_positives'] += int(summary.get(REVERSINGLABS_JSON_TOTAL_POSITIVES, 0))
        tally['total_found'] += int(summary.get(APP_JSON_TOTAL_OBJECTS_SUCCESS, 0))
        tally['total_queried'] += int(summary.get(APP_JSON_TOTAL_OBJECTS_TO_ACT_ON, 0))
        for result in action_results:
            res = {}
            parameter = result.get_param()
            result_summary = result.get_summary()
            # print "summary " + str(result_summary) + " action_results " + str(parameter)
            for dataelem in result.get_data():
                print str(dataelem) + "\n\n\n"
                if 'status' in dataelem:
                    print "status: " + dataelem['status']
                    res['status'] = dataelem['status']
                else:
                    res['status'] = 'Unknown'
                if 'first_seen_on' in dataelem:
                    print "first_seen_on: " + dataelem['first_seen_on']
                    res['first_seen_on'] = dataelem['first_seen_on']
                else:
                    res['first_seen_on'] = ' Not found '
                if 'last_seen_on' in dataelem:
                    print "last_seen_on: " + dataelem['last_seen_on']
                    res['last_seen_on'] = dataelem['last_seen_on']
                else:
                    res['last_seen_on'] = ' Not found '
                if 'sample_type' in dataelem:
                    print "sample_type: " + dataelem['sample_type']
                    res['sample_type'] = dataelem['sample_type']
                else:
                    res['sample_type'] = ' Not Available '
                if 'sample_size' in dataelem:
                    print "sample_size: " + str(dataelem['sample_size'])
                    res['sample_size'] = dataelem['sample_size']
                else:
                    res['sample_size'] = 'Not Available'

                res['threat_name'] = 'Not Available'
                res['trust_factor'] = 'Not Available'
                res['threat_level'] = 'Not Available'

                if 'mwp_result' in dataelem:
                    res['mwp_result'] = dataelem['mwp_result']
                    print "Found mwp result " + str(res['mwp_result'])
                    if 'classification' in dataelem['mwp_result']:
                        res['classification'] = dataelem['mwp_result']['classification']
                    if 'threat_name' in res['mwp_result']:
                        res['threat_name'] = res['mwp_result']['threat_name']
                    if 'trust_factor' in res['mwp_result']:
                        res['trust_factor'] = res['mwp_result']['trust_factor']
                    if 'threat_level' in res['mwp_result']:
                        res['threat_level'] = res['mwp_result']['threat_level']
                    print str(res)
                else:
                    res['classification'] = 'Unknown'
                if 'mwp_result' in res and result_summary.get(REVERSINGLABS_JSON_TOTAL_SCANS, 0) == 0:
                    print "no XREF "
                    results.append((parameter.get(APP_JSON_HASH, '').lower(),
                        res.get('mwp_result', {}).get('scanner_match', 0),
                        res.get('mwp_result', {}).get('scanner_count', 0), res))
                else:
                    results.append((parameter.get(APP_JSON_HASH, '').lower(), result_summary.get(REVERSINGLABS_JSON_POSITIVES, 0),
                                    result_summary.get(REVERSINGLABS_JSON_TOTAL_SCANS, 0), res))
        print("results " + str(results) + " \n*********************************")
    if tally['total_queried']:
        percentage = int((tally['total_positives'] / float(tally['total_queried'])) * 100)
    else:
        percentage = 0
    parameters['percentage'] = percentage
    parameters['result_summary'] = [('Queried', [tally['total_queried']]), ('Found', [tally['total_found']]),
            ('Detected', [tally['total_positives']]), ('Detection ratio', [percentage]), ]

    parameters['additional_text'] = '{percentage}% detection ratio'.format(**parameters)

    context['parameters'] = parameters
    context['results'] = results
    context['title_text_color'] = 'white'
    context['body_color'] = '#0F75BC'
    context['title_color'] = 'white'
    return 'reversinglabs_template.html'
