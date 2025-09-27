#!/usr/bin/env python3

import sys
import os
import re
import socket
import logging
import requests
import json
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_local_ip():
    """Get the local IP address"""
    try:
        # Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def get_auth_token(switch_ip, username, password, debug=False):
    """Get authentication token from Aruba CX switch"""
    if debug:
        logger.debug(f"Getting auth token for {switch_ip}")
        logger.debug(f"Using username: {username}")

    url = f"https://{switch_ip}/rest/v10.04/login"
    params = {'username': username}
    data = {'password': password}

    try:
        response = requests.post(url, params=params, data=data, verify=False, timeout=30)
        if debug:
            logger.debug(f"Auth response status: {response.status_code}")
            logger.debug(f"Auth response headers: {dict(response.headers)}")

        response.raise_for_status()

        # Extract session cookie
        if 'Set-Cookie' in response.headers:
            cookie = response.headers['Set-Cookie'].split(';')[0]
            if debug:
                logger.debug(f"Authentication successful, cookie: {cookie}")
            return cookie
        else:
            logger.error("No session cookie in response")
            if debug:
                logger.debug(f"Auth response text: {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Authentication failed: {e}")
        if debug and hasattr(e, 'response') and e.response is not None:
            logger.debug(f"Auth error response: {e.response.text}")
        return None

def logout(switch_ip, cookie, debug=False):
    """Logout from the switch to free up session"""
    if debug:
        logger.debug("Logging out from switch")

    url = f"https://{switch_ip}/rest/v10.04/logout"
    headers = {'Cookie': cookie}

    try:
        response = requests.post(url, headers=headers, verify=False, timeout=30)
        if debug:
            logger.debug(f"Logout response status: {response.status_code}")
        return response.status_code in [200, 204]
    except requests.exceptions.RequestException as e:
        if debug:
            logger.debug(f"Logout error (but continuing): {e}")
        return False

def get_sflow_config(switch_ip, cookie, debug=False):
    """Get current sFlow configuration"""
    if debug:
        logger.debug("Getting current sFlow configuration")

    url = f"https://{switch_ip}/rest/v10.04/system/sflows/sFlow"
    headers = {'Cookie': cookie}

    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30)
        if debug:
            logger.debug(f"sFlow GET response status: {response.status_code}")
            if response.text:
                logger.debug(f"sFlow GET response: {response.text[:500]}...")

        if response.status_code == 404:
            if debug:
                logger.debug("No existing sFlow configuration found")
            return None
        elif response.status_code == 200:
            data = response.json()
            if debug:
                logger.debug(f"sFlow config data: {json.dumps(data, indent=2)}")
            return data
        else:
            response.raise_for_status()
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            logger.debug(f"Error getting sFlow configuration: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing sFlow JSON response: {e}")
        return None

def get_sflow_collectors(switch_ip, cookie, debug=False):
    """Get current sFlow collectors"""
    if debug:
        logger.debug("Getting current sFlow collectors")

    url = f"https://{switch_ip}/rest/v10.04/system/sflows/sFlow/collectors"
    headers = {'Cookie': cookie}

    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30)
        if debug:
            logger.debug(f"Collectors GET response status: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            if debug:
                logger.debug(f"sFlow collectors data: {json.dumps(data, indent=2)}")
            return data
        else:
            return {}
    except requests.exceptions.RequestException as e:
        logger.warning(f"Error getting sFlow collectors: {e}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing collectors JSON response: {e}")
        return {}

def create_sflow_config(switch_ip, cookie, collector_ip, debug=False):
    """Create new sFlow configuration"""
    if debug:
        logger.debug(f"Creating new sFlow configuration")

    # Create main sFlow configuration
    url = f"https://{switch_ip}/rest/v10.04/system/sflows"
    headers = {
        'Cookie': cookie,
        'Content-Type': 'application/json'
    }

    sflow_data = {
        "name": "sFlow",
        "enabled": True,
        "agent_address": "localhost",
        "polling": 20,
        "sampling": 2048
    }

    if debug:
        logger.debug(f"Creating sFlow instance with data: {json.dumps(sflow_data, indent=2)}")

    try:
        response = requests.post(url, headers=headers, json=sflow_data, verify=False, timeout=30)
        if debug:
            logger.debug(f"sFlow POST response status: {response.status_code}")
            logger.debug(f"sFlow POST response: {response.text}")

        if response.status_code not in [201, 204]:
            logger.error(f"Failed to create sFlow instance: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating sFlow instance: {e}")
        return False

    # Create collector for this sFlow instance
    collector_url = f"https://{switch_ip}/rest/v10.04/system/sflows/sFlow/collectors"
    collector_data = {
        "ip_address": collector_ip,
        "udp_port": 6343,
        "vrf": "/rest/v10.04/system/vrfs/default"
    }

    if debug:
        logger.debug(f"Creating sFlow collector with data: {json.dumps(collector_data, indent=2)}")

    try:
        response = requests.post(collector_url, headers=headers, json=collector_data, verify=False, timeout=30)
        if debug:
            logger.debug(f"Collector POST response status: {response.status_code}")
            logger.debug(f"Collector POST response: {response.text}")

        if response.status_code not in [201, 204]:
            logger.error(f"Failed to create sFlow collector: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating sFlow collector: {e}")
        return False

    return True

def update_sflow_collector(switch_ip, cookie, collector_ip, debug=False):
    """Update existing sFlow collector IP only if different"""
    if debug:
        logger.debug(f"Checking if sFlow collectors need updating to {collector_ip}")

    # Get existing collectors
    collectors = get_sflow_collectors(switch_ip, cookie, debug)

    # Check if we already have the target collector
    target_found = False
    for collector_key, collector_ref in collectors.items():
        # Parse IP from the key (format: "vrf,ip_address,udp_port")
        try:
            parts = collector_key.split(',')
            if len(parts) >= 3 and parts[1] == collector_ip:
                if debug:
                    logger.debug(f"Target collector {collector_ip} already exists")
                print(f"Target collector {collector_ip} already configured")
                return True
        except:
            continue

    if debug:
        logger.debug("Target collector not found, updating...")
        if collectors:
            logger.debug(f"Existing collectors to remove: {list(collectors.keys())}")

    headers = {
        'Cookie': cookie,
        'Content-Type': 'application/json'
    }

    # Delete all existing collectors
    for collector_key in collectors:
        if debug:
            logger.debug(f"Deleting collector: {collector_key}")

        # The collector_key is in format "vrf,ip_address,udp_port"
        # We need to URL encode it properly
        encoded_key = collector_key.replace('/', '%2F').replace(',', '%2C')
        delete_url = f"https://{switch_ip}/rest/v10.04/system/sflows/sFlow/collectors/{encoded_key}"

        try:
            response = requests.delete(delete_url, headers=headers, verify=False, timeout=30)
            if debug:
                logger.debug(f"Delete collector {collector_key} response status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error deleting collector {collector_key}: {e}")

    # Create new collector with target IP
    collector_url = f"https://{switch_ip}/rest/v10.04/system/sflows/sFlow/collectors"
    collector_data = {
        "ip_address": collector_ip,
        "udp_port": 6343,
        "vrf": "/rest/v10.04/system/vrfs/default"
    }

    if debug:
        logger.debug(f"Creating new collector with data: {json.dumps(collector_data, indent=2)}")

    try:
        response = requests.post(collector_url, headers=headers, json=collector_data, verify=False, timeout=30)
        if debug:
            logger.debug(f"New collector POST response status: {response.status_code}")
            logger.debug(f"New collector POST response: {response.text}")

        if response.status_code not in [201, 204]:
            logger.error(f"Failed to create new collector: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating new collector: {e}")
        return False

    return True

def main():
    # Parse command line arguments
    debug = False
    args = sys.argv[1:]

    # Check for debug flag
    if '-d' in args or '--debug' in args:
        debug = True
        logger.setLevel(logging.DEBUG)
        # Remove debug flags from args
        args = [arg for arg in args if arg not in ['-d', '--debug']]
        logger.debug("Debug mode enabled")

    if len(args) < 1:
        print("Usage: {} [-d|--debug] <switch_ip> [collector_ip] [username]".format(sys.argv[0]))
        print("  -d, --debug    Enable debug logging")
        print("Environment variables:")
        print("  CX_USER        Admin username (default: admin)")
        print("  CX_PASS        Admin password (required)")
        sys.exit(1)

    switch_ip = args[0]

    # Determine collector IP
    collector_ip = args[1] if len(args) > 1 else get_local_ip()
    if len(args) <= 1:
        print(f"Using local IP {collector_ip} as collector")

    # Determine username from env or argument
    if len(args) > 2:
        username = args[2]
    else:
        username = os.getenv('CX_USER', 'admin')
    print(f"Using username: {username}")

    # Get password from environment variable
    password = os.getenv('CX_PASS')
    if not password:
        logger.error("CX_PASS environment variable is required")
        sys.exit(1)

    if debug:
        logger.debug(f"Parsed arguments - Switch: {switch_ip}, Collector: {collector_ip}, Username: {username}")

    # Get authentication token
    cookie = get_auth_token(switch_ip, username, password, debug)
    if not cookie:
        logger.error("Failed to authenticate with switch")
        sys.exit(1)

    # Track if we need to logout
    session_active = True

    try:
        # Check current sFlow configuration
        sflow_config = get_sflow_config(switch_ip, cookie, debug)

        if sflow_config is None:
            print("No existing sFlow configuration found. Creating new configuration...")
            success = create_sflow_config(switch_ip, cookie, collector_ip, debug)
            if success:
                print("sFlow configuration created successfully")
            else:
                logger.error("Failed to create sFlow configuration")
                sys.exit(1)
        else:
            print("Existing sFlow configuration found. Checking collectors...")
            success = update_sflow_collector(switch_ip, cookie, collector_ip, debug)
            if success:
                print("sFlow configuration verified/updated successfully")
            else:
                logger.error("Failed to update sFlow collectors")
                sys.exit(1)

        print("Configuration completed successfully")

    finally:
        # Always logout to free up session
        if session_active:
            logout(switch_ip, cookie, debug)

if __name__ == "__main__":
    main()
