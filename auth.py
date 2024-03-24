#!/usr/bin/env python3

"""A script to automatically login to fortinet firewall captive portal.

Given a username and password this script automatically monitors the network and logs in to the fortinet captive portal
when needed. It also send keepalive requests periodically to maintain the login.
"""

import argparse
import getpass
import logging
import re
import requests
import signal
import time
from typing import Tuple, Union

# URL constants.
ONE_ONE_ONE_ONE = 'http://1.1.1.1/'
ONE_ONE_ONE_ONE_HTTPS = 'https://1.1.1.1/'

# Using globals here help bypass passing a few arguments.
logged_in = False
logout_url = ''


def interrupt_handler(sig, frame):
    """SIGINT handler. Logout user if they are logged in."""
    if logged_in:
        try:
            response = requests.get(logout_url, headers={'User-Agent': 'Mozilla/5.0'})
        except:
            logging.error(f'Error in opening url: {logout_url}.')

        if response.status_code == 200:
            logging.info('Successfully logged out.')
    else:
        logging.info('Exiting.')

    exit()


def get_credentials(pass_only: bool) -> Tuple[Union[str, None], str]:
    """Prompt for credential input.

    Parameters
    ----------
    pass_only : bool
        If True only prompts for password.

    Returns
    -------
    username : str | None
        Username. If pass_only is True this is None.
    password : str
        Password.
    """
    # Get username/password.
    username = None
    if not pass_only:
        username = input('Username: ')
    password = getpass.getpass('Password: ')

    return username, password


def state_check() -> Tuple[bool, requests.Response]:
    """Checks whether user is currently logged in or not.

    Returns
    -------
    bool
        Indicates whether the user is logged in.
    requests.Response
        The Response object.
    """
    # Keep trying to reach http://1.1.1.1 until status code is 200.
    while True:
        try:
            response = requests.get(ONE_ONE_ONE_ONE, headers={'User-Agent': 'Mozilla/5.0'})
        except requests.exceptions.RequestException:
            logging.error(f'Error in opening url: {ONE_ONE_ONE_ONE}. Retrying ...')
            continue

        if response.status_code == 200:
            break

    # If redirected url is https://1.1.1.1/ then user is probably logged in.
    if response.url == ONE_ONE_ONE_ONE_HTTPS:
        return True, response
    else:
        return False, response


def login(username: str, password: str, response: requests.Response) -> Tuple[bool, Union[requests.Response, None]]:
    """Try logging in to the network via the captive portal.

    Parameters
    ----------
    username : str
        Username.
    Password : str
        Password.
    response : requests.Response
        Response object for captive portal.

    Returns
    -------
    bool
        Login status.
    requests.Response | None
        The Response object (or None is response is not valid).
    """
    global logged_in
    global logout_url

    # Extract base url and magic token.
    url = re.search('https://[a-z:0-9.]*/', response.url)
    if url is None:
        logging.error('Could not find base url via regex match. Exiting.')
        exit()
    url = url[0]
    magic: str = re.search('(name="magic" value=")([a-zA-Z0-9]+)(")', response.text)
    if magic is None:
        logging.error('Could not find magic value via regex match. Exiting.')
        exit()
    magic = magic[2]

    # Prepare data.
    data = {
        'username': username,
        'password': password,
        'magic': magic,
        '4Tredir': '/'
    }

    # Try to log in to the network.
    try:
        response = requests.post(url, headers={'User-Agent': 'Mozilla/5.0'}, data=data)
    except requests.exceptions.RequestException:
        logging.error(f'Error in opening url: {url}.')
        return False, None

    if response.status_code != 200:
        return False, response

    # We should get a javascript redirect else username/password is probably wrong.
    url = re.search(r'window.location="(.*)"', response.text)
    if url is None:
        logging.error('Invalid username/password. Exiting.')
        exit()
    url = url[1]
    response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
    if response.status_code != 200:
        logging.error('Failed to fetch keepalive webpage.')
        return False, response

    logging.info(f'Successfully logged in. Keepalive url: {url}')

    logged_in = True
    logout_url = url.replace('keepalive', 'logout')

    return True, response


def keepalive(url: str, keepalive_time: int) -> None:
    """Send keepalive requests.

    Parameters
    ----------
    url : str
        Keepalive url.
    keepalive_time : int
        Seconds to wait between keepalive requests.
    """
    global logged_in

    # Keep sending keepalive requests every KEEPALIVE_TIME seconds.
    while True:
        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        except requests.exceptions.RequestException:
            logging.error(f'Error in opening url: {url}.')
            logged_in = False
            break

        # Ensure that no redirect occurs.
        if response.status_code == 200 and response.url == url:
            logging.info(f'Keeping alive ({keepalive_time} secs) ...')
            time.sleep(keepalive_time)
            continue

        else:
            logging.error('Something went wrong.')
            logged_in = False
            break


def main() -> None:
    """Main function for the script."""
    # Parse arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', help='Username', default='srujanas22')
    parser.add_argument('-p', '--password', help='Password', default='$rujanaS41')
    parser.add_argument('-r', '--retry_time', help='Seconds to wait before retrying', type=int, default=30)
    parser.add_argument('-k', '--keepalive_time', help='Seconds to wait between keepalives', type=int, default=60)
    args = parser.parse_args()

    # Get credentials if needed.
    if args.username is None and args.password is None:
        username, password = get_credentials(False)
    elif args.username is None and args.password is not None:
        print('Please supply a username.')
        exit()
    elif args.username is not None and args.password is None:
        username: str = args.username
        _, password = get_credentials(True)
    else:
        username: str = args.username
        password: str = args.password

    # Setup logging.
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)

    # Setup interrupt handler.
    signal.signal(signal.SIGINT, interrupt_handler)

    # Keep running a loop which checks current state, logs in and keeps alive.
    while True:
        logging.info('Checking state ...')
        status, response = state_check()

        # If already logged in, wait for a while and retry.
        if status:
            logging.info(f'Seems to be already logged in. Sleeping for {args.retry_time} seconds.')
            time.sleep(args.retry_time)
            continue

        # If not logged in, try to log in. Redirection is handled via javascript, so extract the redirected url.
        url = re.search(r'window.location="(.*)"', response.text)[1]

        logging.info(f'Not logged in. Captive portal url: {url}')

        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code != 200:
            logging.error('Failed to fetch captive portal webpage. Retrying...')
            continue
        status, response = login(username, password, response)

        # If log in was unsuccessful retry loop.
        if not status:
            continue

        # Send keepalive requests.
        keepalive(response.url, args.keepalive_time)


if __name__ == '__main__':
    main()