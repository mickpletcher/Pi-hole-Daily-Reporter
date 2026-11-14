"""Fail closed on real network access in CI, including Python child workers."""
import sys


def deny_network(event, args):
    if event in {'socket.connect', 'socket.bind', 'socket.getaddrinfo',
                 'socket.gethostbyname', 'socket.gethostbyaddr', 'socket.sendto'}:
        raise RuntimeError('CI forbids real network access: ' + event)


sys.addaudithook(deny_network)
