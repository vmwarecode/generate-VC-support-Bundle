#!/usr/bin/env python
import json
import sys
import logging
import argparse

import requests.packages.urllib3.exceptions
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

""" 
  Please refer following links for more information
  https://developer.vmware.com/docs/vsphere-automation/latest/
  https://developer.vmware.com/apis/vsphere-automation/latest/vcenter/services/service/
"""

# Create session and set it to ssl verify False
session = requests.session()
session.verify = False
api_session_url = "https://{}/api/session"
api_get_services = "https://{}/api/vcenter/services"


def setup_logging():
    # create logger
    logger = logging.getLogger("vcenter_services_health_check.py")
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
    parser.add_argument("--vc_user_name", dest="vc_user_name", default="administrator@vsphere.local",
                        action="store", required=True, help="vCenter userName")
    parser.add_argument("--vc_password", dest="vc_password", default="Admin!23",
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


def get_services_state(vcip, session_id):
    """
    :param vcip:
    :param session_id:
    :return:
    """
    request_url = api_get_services.format(vcip)
    log.info("Sending API request: GET " + request_url)
    return session.get(api_get_services.format(vcip, "session"), headers={"vmware-api-session-id": session_id})


def run_verify_services_state():
    args = argument_parser()
    service_status_verification = True
    health_fail_services_count = 0
    not_running_services_count = 0
    health_fail_services = []
    not_running_services = []
    if args.vc_ip is None:
        raise ValueError("VC IP is not provided aborting the test")
    session_id = get_session_id(args.vc_ip, args.vc_user_name, args.vc_password)
    if session_id is not None:
        log.info("session id :: {}".format(session_id))
        service_state = get_services_state(args.vc_ip, session_id)
        if service_state.status_code == 200:
            service_status_verification = True
            log.info("Services List and Status:" +
                     json.dumps(service_state.json(), indent=2, sort_keys=True))
            service_output = service_state.json()
            for key, value in service_output.items():
                log.info("Service name : {}".format(key))
                log.info("Services Status:" +
                         json.dumps(value, indent=2, sort_keys=True))
                if value["startup_type"] == "AUTOMATIC":
                    if value["state"] == "STARTED":
                        log.info("Service is running, proceeding to verify the health")
                        if value["health"] == "HEALTHY":
                            log.info("Service status is healthy")
                        else:
                            log.error("{} Service status is not healthy".format(key))
                            health_fail_services_count = health_fail_services_count + 1
                            health_fail_services.append(key)
                    else:
                        log.error("{} service is not running".format(key))
                        log.error("Service is not running considering health status as failed")
                        not_running_services_count = not_running_services_count + 1
                        not_running_services.append(key)
        else:
            log.error("Failed to get service status")
            service_status_verification = False
        delete_session(args.vc_ip, session_id)

    if service_status_verification and health_fail_services_count == 0 and not_running_services_count == 0:
        log.info("vCenter services health verification has been passed")
    else:
        log.error("vCenter services health verification has been Failed")
        log.info("Number_of_services_not_running:{}".format(not_running_services_count))
        log.info("Services not running:{}".format(not_running_services))
        log.info("Number_of_services_not_healthy:{}".format(health_fail_services_count))
        log.info("Services not healthy:{}".format(health_fail_services))
        sys.exit(1)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    run_verify_services_state()
