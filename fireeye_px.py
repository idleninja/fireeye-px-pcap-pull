#!/usr/bin/python
# Brett Gross
# todo: 
# wishful thinking: multi-threading/background request.

import requests, json, ast, datetime, argparse
from time import sleep
from getpass import getpass
from base64 import b64encode, b64decode
try:
	from requests.packages.urllib3.exceptions import InsecureRequestWarning
	# Disable certificate/validation warnings.
	requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except (ImportError):
	pass

debug = False
https_proxy = None
hostname = ""
pcap_time_window = 5
filter_options = {'0': 'alertBody',
 '1': 'alertID',
 '10': 'applicationId',
 '11': 'applicationName',
 '12': 'biflowDirection',
 '13': 'cc',
 '14': 'channel',
 '15': 'cmd',
 '16': 'command',
 '17': 'command_str',
 '18': 'dest_ip',
 '19': 'dest_port',
 '2': 'alertSeverity',
 '20': 'destinationEtherAddress',
 '21': 'destinationIPv4Address',
 '22': 'destinationIPv6Address',
 '23': 'destinationTransportPort',
 '24': 'deviceAlertType',
 '25': 'deviceType',
 '26': 'dnsFlags',
 '27': 'dnsId',
 '28': 'dnsIsResponse',
 '29': 'dnsQName',
 '3': 'alertUrl',
 '30': 'dnsQRType',
 '31': 'dnsRCode',
 '32': 'dnsTTL',
 '33': 'dnsTXTData',
 '34': 'doc_values_type',
 '35': 'droppedOctetDeltaCount',
 '36': 'droppedOctetDeltaCountReverse',
 '37': 'droppedPacketDeltaCount',
 '38': 'droppedPacketDeltaCountReverse',
 '39': 'dstLocation__area_code',
 '4': 'answer__rdata',
 '40': 'dstLocation__city',
 '41': 'dstLocation__continent',
 '42': 'dstLocation__country_code',
 '43': 'dstLocation__country_code3',
 '44': 'dstLocation__country_name',
 '45': 'dstLocation__latitude',
'46': 'dstLocation__longitude',
 '47': 'dstLocation__metro_code',
 '48': 'dstLocation__postal_code',
 '49': 'dstLocation__region',
 '5': 'answer__rrname',
 '50': 'egressInterface',
 '51': 'ethernetProtocol',
 '52': 'event_id',
 '53': 'event_type',
 '54': 'exporterFQDN',
 '55': 'exporterIPv4Address',
 '56': 'exporterIPv6Address',
 '57': 'fid',
 '58': 'fileDirectory',
 '59': 'fileMD5',
 '6': 'answer__rrtype',
 '60': 'fileMagic',
 '61': 'fileName',
 '62': 'fileSize',
 '63': 'fileState',
 '64': 'fileStored',
 '65': 'fileSuffix',
 '66': 'flowEndNanoseconds',
 '67': 'flowEndReason',
 '68': 'flowStartNanoseconds',
 '69': 'flow_id',
 '7': 'answer__ttl',
 '70': 'fragmentFlags',
 '71': 'fragmentFlagsReverse',
 '72': 'ftpReplyCode',
 '73': 'ftpReplyData',
 '74': 'ftpUser',
 '75': 'httpContentLength',
 '76': 'httpContentType',
 '77': 'httpGet',
 '78': 'httpHost',
 '79': 'httpMethod',
 '8': 'appType',
 '80': 'httpReferer',
 '81': 'httpResponse',
 '82': 'httpURL',
 '83': 'httpUserAgent',
 '84': 'httpVersion',
 '85': 'httpX-Forwaded-For',
 '86': 'ingressInterface',
 '87': 'ioc_alert_title',
 '88': 'ipClassOfService',
 '89': 'ipVersion',
 '9': 'app_proto',
 '90': 'mailAttachment',
 '91': 'mailFrom',
 '92': 'mailHello',
 '93': 'mailRecipientToList',
 '94': 'mailStatus',
 '95': 'mailTo',
 '96': 'mid',
 '97': 'msg',
 '98': 'nickname',
 '99': 'notafter',
 '100': 'notbefore',
 '101': 'npulseFlowHash',
 '102': 'observationTimeDay',
 '103': 'observationTimeMonth',
 '104': 'observationTimeYear',
 '105': 'OR operator',
 '106': 'AND operator',
 '107': 'NOT operator',
 '999': '*Advanced Mode*'}

def process_args():
	parser = argparse.ArgumentParser(description='FireEye PCAP Query (Non-RESTful)')
	parser.add_argument('--cq', metavar="<custom_query>", type=str, help='Run custom query.')
	parser.add_argument('--fo', action='store_const', const=str, help='Print filter options.')
	parser.add_argument('--out', metavar="<output_filename>", type=str, help='Save PCAP to file.')
	return parser.parse_args()

def write_pcap(resp, filename="/tmp/fe_capture.pcap"):
	with open(filename, "wb") as f:
		for chunk in resp.iter_content(chunk_size=128):
			f.write(chunk)

def get_event_time():
	event_time = ""
	try:
		event_time = datetime.datetime.strptime(raw_input("Enter the UTC event datetime (2018-08-09 20:51:17): ").strip(), "%Y-%m-%d %H:%M:%S")
	except (ValueError):
		print("Invalid event datetime input. Try again.")
		event_time = get_event_time()
	return event_time
	
def get_user_input(msg="", user_input="", num_ans=False):
	error = True
	while error:
		user_input = raw_input(msg).strip()
		if not user_input:
			print("No input received. Try again.\n")
		elif num_ans and not user_input.isdigit():
			print("Invalid input received. Try again.\n")
		else:
			error = False
	return user_input
	
def print_filter_opts():
	print("\nPCAP Request Options\n")
	for k in sorted(filter_options.keys(), key=int):
		print("%s. %s" % (k, filter_options[k]))
	print("")

def request_info(custom_query=""):
	gte_date = lte_date = ""
	filter_query = ""

	if custom_query:
		filter_query = custom_query
	else:
		print_filter_opts()

		constructing_query = True
		while constructing_query:
			filter_opt_key = get_user_input("Enter the numerical option you want to include in the filter: ", num_ans=True)
			# Custom/Advance Mode
			if filter_opt_key == "999":
				print("Example format: 'destinationIPv4Address: 127.0.0.1 OR destinationIPv4Address: 127.0.0.2'")
				filter_query = get_user_input("Query: ")
				constructing_query = False
			# Construct filter query mode
			else:
				if "operator" in filter_options[filter_opt_key]:
					filter_query += " %s " % filter_options[filter_opt_key].strip(" operator")
				else:
					filter_opt_val = get_user_input("Enter value for option '%s': " % filter_options[filter_opt_key])
					filter_query += "%s: %s" % (filter_options[filter_opt_key], filter_opt_val)
			print("\nYour query:\n%s\n\n" % filter_query)
			if get_user_input("Is query complete? [y/n]: ").strip().lower() in ["y", "yes"]:
				constructing_query = False
			else:
				constructing_query = True

	# Prompt for event datetime and calc 10m window for PCAP request.
	event_time = get_event_time()
	gte_date = event_time - datetime.timedelta(minutes=pcap_time_window)
	lte_date = event_time + datetime.timedelta(minutes=pcap_time_window)

	return filter_query,gte_date,lte_date

def request_creds(username="", password=""):
	username = raw_input("Please enter your FireEye username: ").strip()
	password = getpass().strip()
	if not username or not password: 
		print("Empty username or password. Try again.\n")
		username, password = request_creds()
	return username, password

def main():
	opts = process_args()
	more_pcaps = True
	basic_auth = ""

	if opts.fo:
		print_filter_opts()
		exit()

	while more_pcaps:
		# Upfront questions to beging PCAP pull.
		filter_query,gte_date,lte_date = request_info(custom_query=opts.cq)
		start_date = gte_date.strftime("%Y.%m.%d")
		end_date = lte_date.strftime("%Y.%m.%d")
		data = json.dumps({"sort":[{"@timestamp":{"order":"desc"}}],"query":{"filtered":{"query":{"query_string":{"query":"%s" % filter_query,"lowercase_expanded_terms":"false"}},"filter":{"bool":{"must":[{"range":{"@timestamp":{"gte":gte_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),"lte":lte_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")}}}],"should":[],"must_not":[]}}}},"from":0,"size":250,"aggs":{"first_event":{"min":{"field":"@timestamp"}},"last_event":{"max":{"field":"@timestamp"}}}})

		# Request FireEye credentials.
		if not basic_auth:
			basic_auth = "Basic %s" % b64encode(":".join(request_creds()))

			# Start Requests session and make authentication request.
			session = requests.Session()
			session.trust_env = False
			session.headers.update({"Authorization": basic_auth})
			print("\nAttempting Login")
			session.post("https://%s/login" % hostname, proxies={"https":https_proxy}, verify=False, allow_redirects=True)

		if debug: print("\ndata:\n%s" % data)

		# Perform request for filtered query.
		print("Making query request")
		query_response = session.post("https://%s/elasticsearch/nspector-%s,alert-%s/_search?ignore_unavailable=true" % (hostname, start_date, end_date), data=data, proxies={"https":https_proxy}, verify=False, allow_redirects=True)
		
		if debug: print("\nquery_response.text:\n%s" % query_response.text)

		if query_response.text and "no valid authentication" not in query_response.text:
			# Parse the HTTP response containing the alerts/pxFlows.
			j = json.loads(query_response.text)
			l = []
			for item in j['hits']['hits']:
				# Only use the pxflow types as they ARE the PCAPs.
				if "pxflow" in item['_type']:
					d = {}
					try:
					    d["saddr"] = item['_source']['sourceIPv4Address']
					    d["daddr"] = item['_source']['destinationIPv4Address']
					    d["proto"] = item['_source']['protocolIdentifier']
					    d["sport"] = item['_source']['sourceTransportPort']
					    d["dport"] = item['_source']['destinationTransportPort']
					    d["start"] = item['_source']['flowStartNanoseconds']
					    d["end"] = item['_source']['flowEndNanoseconds']
					    d["npulseFlowHash"] = item['_source']['npulseFlowHash']
					    d["index_name"] = item['_index']
					    d["exporter"] = item['_source']['exporterIPv4Address']
					    l.append(d)
					except KeyError:
					    pass

			flow_data = ""
			if len(l) == 0:
				print("Error: No pxflows returned for filter options. Revise your query and try again.")
			else:
				# Generate the HTTP request payload to start the PCAP acquisition.
				flow_data = json.dumps({"FileParse": "true", "flows": ast.literal_eval(json.dumps(l))})
				
			if debug:
				print("\nFlow data:\n %s" % flow_data)

		# Make the request for the PCAPs.
		if flow_data:
			print("Making pxflows request")
			pxflow_response = session.post("https://%s/nspector-pivotengine/create/" % hostname, data=flow_data, proxies={"https":https_proxy}, verify=False, allow_redirects=True)

		# Parse/store the pcap_id value to use in subsequent status checks.
		pcap_id = ""
		pcap_status = ""
		attempt_num = 90
		max_download_attempts = 2
		pxflow_response = ""		
		if type(pxflow_response) != str and pxflow_response.text:
			pcap_id = json.loads(pxflow_response.text)["data"]["pcap_id"]
			# Loop through 'status check' requests to know when PCAP is ready for download or failed :( 
			while "done" not in pcap_status and attempt_num < max_download_attempts:
				if pcap_status in ["failed", "not_requested"]:
					print("Request failed.")
					break
				# Make request to check if PCAP is ready for download.
				status_response = session.get("https://%s/nspector-pivotengine/extractionStatus/%s" % (hostname, pcap_id))
				pcap_status = json.loads(status_response.text)["request_status"]["status"]
				attempt_num += 1
				print("Checking PCAP status. Attempt: %s. Status: %s" % (attempt_num, pcap_status))
				sleep(3)
				if attempt_num == max_download_attempts:
					print("PCAP is taking a looong time.\n")
					more_time = raw_input("Would you like more time to process PCAP? [Y/n]: ").strip()
					if more_time.lower() in ['y', 'yes']:
						max_download_attempts += 50
					else:
						print("Max attempts reached. PCAP processing took too long.")

		# loop through until pcap is available to download or time expired.
		if "done" in pcap_status:
			print("Requesting PCAP to download")
			# Make request to download the raw PCAP. 
			# Note: I did notice it appears the magic numbers for the PCAP are swapped.
			# IDK if FireEye is doing something tricky or this is expected behavior.
			# Wireshark loads the resulting PCAP fine but file command identifies it as 'data'.
			download_response = session.get("https://%s/nspector-pivotengine/download/%s" % (hostname, pcap_id), proxies={"https":https_proxy}, verify=False, allow_redirects=True, stream=True)
			if opts.out:
				write_pcap(download_response, opts.out)
			else:
				write_pcap(download_response)

			if debug:
				print(pcap_id)
				print(session.cookies)
				print(download_response.status_code)
			print("Wrote pcap to /tmp/temp.pcap")
		else:
			print("Unable to pull requested PCAP.")

		if basic_auth:
			if get_user_input("Make another PCAP request? [y/n]: ").strip().lower() in ["y", "yes"]:
				more_pcaps = True
			else:
				more_pcaps = False

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt):
        print("^C")
        exit()
