# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0

import socket
from time import sleep

from bookshelf.api_v2.logging_helpers import log_yellow


def is_ssh_available(host, port=22):
    """ checks if ssh port is open """
    s = socket.socket()
    try:
        s.connect((host, port))
        return True
    except:
        return False


def wait_for_ssh(host, port=22, timeout=600):
    """ probes the ssh port and waits until it is available """
    log_yellow('waiting for ssh...')
    for iteration in xrange(1, timeout): #noqa
        sleep(1)
        if is_ssh_available(host, port):
            return True
        else:
            log_yellow('waiting for ssh...')
