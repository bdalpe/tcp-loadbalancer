import argparse
import os


class InvalidInput(Exception):
    pass


def parse_host_and_port(host):
    """
    Converts a string representation of a host and port to a tuple.

    :param host: e.g. 192.168.1.1:5555
    :return: e.g. ('192.168.1.1', 5555)
    """

    a = host.strip().split(':')
    if len(a) != 2:
        raise InvalidInput(f"Unable to parse {host}")
    return str(a[0]), int(a[1])


def parse_host_and_port_list(hosts):
    """
    Converts a comma separated list of hosts and ports to an array of tuples.

    :param hosts: e.g. 192.168.1.1:5555,192.168.1.2:5555,192.168.1.3:5555
    :return: e.g. [('192.168.1.1', 5555), ('192.168.1.2', 5555), ('192.168.1.3', 5555)]
    """

    return [parse_host_and_port(i.strip()) for i in hosts.split(',')]


class EnvDefault(argparse.Action):
    """
    Custom handler for argparse

    Order of priority:
    (Lowest) argparse default -> ENV -> CLI flag (Highest)
    """
    def __init__(self, envvar, required=True, default=None, **kwargs):
        if envvar in os.environ:
            default = os.environ[envvar]
        if required and default:
            required = False
        super(EnvDefault, self).__init__(default=default, required=required, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
