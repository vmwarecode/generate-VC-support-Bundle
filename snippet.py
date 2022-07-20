#!/usr/bin/env python
import json
import sys
import logging
import time
import argparse

import requests.packages.urllib3.exceptions
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

""" 
  Please refer following links for more information
  https://developer.vmware.com/docs/vsphere-automation/latest/
"""

# Create session and set it to ssl verify False
session = requests.session()
session.verify = False
api_session_url = "https://{}/api/session"
api_get_components = "https://{}/api/appliance/support-bundle/components"
api_create_supportbundle = "https://{}/api/appliance/support-bundle?vmw-task=true"
api_supportbundle_download_status = "https://{}/api/appliance/support-bundle?size=1"


def setup_logging():
    # create logger
    logger = logging.getLogger("generate_vc_supportbundle.py")
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)
    return logger


# Start log function
log = setup_logging()


# Argument parser
def argument_parser():
    parser = argparse.ArgumentParser("Parsing command line arguments")
    parser.add_argument("--vc_ip", dest="vc_ip", default=None,
                        action="store", required=True, help="Vcenter IP address")
    parser.add_argument("--vc_user_name", dest="vc_user_name", default="",
                        action="store", required=True, help="vCenter userName")
    parser.add_argument("--vc_password", dest="vc_password", default="",
                        action="store", required=True, help="vCenter Password")
    return parser.parse_args()


def create_session(vcip, username, password):
    """
    Creates a session with the API. This is the equivalent of login
    """
    request_url = api_session_url.format(vcip)
    log.info("Sending API request: POST " + request_url)
    return session.post(request_url, auth=(username, password))


def get_session(vcip, session_id):
    """
    Returns information about the current session
    """
    request_url = api_session_url.format(vcip)
    log.info("Sending API request: GET " + request_url)
    return session.get(api_session_url.format(vcip, "session"), headers={"vmware-api-session-id": session_id})


def delete_session(vcip, session_id):
    """
    Terminates the validity of a session token.
    """
    request_url = api_session_url.format(vcip)
    log.info("Sending API request: DELETE " + request_url)
    return session.delete(api_session_url.format(vcip, "session"), headers={"vmware-api-session-id": session_id})


def get_session_id(vcip, username, password):
    """
    Returns the login session id for the given VC
    :param vcip: IP address of the VC machine
    :param username: VI username
    :param password: VI userPassword
    :return: Session ID
    """
    output = create_session(vcip, username, password)
    if output.status_code == 201:
        return output.json()


def get_support_bundle_components(vcip, session_id):
    """
    :param vcip:
    :param session_id:
    :return:
    """
    request_url = api_get_components.format(vcip)
    log.info("Sending API request: GET " + request_url)
    return session.get(request_url, headers={'vmware-api-session-id': session_id})


def create_support_bundle(vcip, session_id):
    """
    :param vcip:
    :param session_id:
    :return:
    """
    data = {"description": "Generate Support bundle"}
    request_body = json.dumps(data)
    request_url = api_create_supportbundle.format(vcip)
    log.info("Sending API request: POST " + request_url)
    return session.post(request_url, headers={'vmware-api-session-id': session_id,
                                'Content-type': 'application/json',
                                'Accept': '*/*'}, data=request_body)


def check_supportbundle_status(vcip, session_id):
    """
    :param vcip:
    :param session_id:
    :return:
    """
    request_url = api_supportbundle_download_status.format(vcip)
    log.info("Sending API request: GET " + request_url)
    return session.get(request_url, headers={'vmware-api-session-id': session_id})


def run_generate_vcsupportbundle_test():
    test_status = False
    args = argument_parser()
    if args.vc_ip is None:
        raise ValueError("VC IP is not provided aborting the test")
    support_bundle_download_url = None
    generate_status_check = True
    session_id = get_session_id(args.vc_ip, args.vc_user_name, args.vc_password)
    if session_id is not None:
        log.info("session id :: {}".format(session_id))
        task_id = create_support_bundle(args.vc_ip, session_id)
        if task_id.status_code == 202:
            log.info("Generate support bundle task creation is successful")
            log.info("Generate support bundle create task ID :: {}".format(task_id.json()))
            i = 1
            timeout = 1200
            timer = 0
            while generate_status_check:
                task_status = check_supportbundle_status(args.vc_ip, session_id)
                if task_status.status_code == 200:
                    log.info("Getting generate support bundle task status is Success")
                    log.info("Generate Support bundle status check::{}".format(i))
                    log.info("Operation is still in progress sleeping for 60 more seconds")
                    time.sleep(60)
                    timer = timer + 60
                    log.info("Total wait time in SECONDS :: {}".format(timer))
                    log.info("STATUS output :" +
                             json.dumps(task_status.json(), indent=2, sort_keys=True))
                    json_data = task_status.json()
                    download_status = json_data["supportbundle_operations"][0]["status"]
                    log.info("Support bundle generate status : {}" .format(download_status))
                    if download_status == "SUCCEEDED":
                        log.info("Support bundle is generated successfully")
                        support_bundle_download_url = json_data["supportbundle_operations"][0]["url"]
                        generate_status_check = False
                        test_status = True
                i = i + 1
                timeout = timeout - 60
                if timeout <= 0:
                    log.error("Generate support bundle operation is timed out")
                    break
    delete_session(args.vc_ip, session_id)
    if test_status:
        log.info("Generate support bundle test executed successfully")
        return support_bundle_download_url
    else:
        log.error("Generate support bundle test failed")
        sys.exit(1)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    sb_download_url = run_generate_vcsupportbundle_test()
    log.info("Support bundle download URL : {}".format(sb_download_url))
