#!/usr/bin/env python
import argparse, socket, sys, time
from subprocess import Popen, PIPE
from importlib import import_module

from twisted.internet import reactor
from twisted.web.server import Site


class MockServer():
    def __init__(self, resource):
        self.resource = '{}.{}'.format(resource.__module__, resource.__name__)
        self.proc = None
        host = socket.gethostbyname(socket.gethostname())
        self.root_url = 'http://%s:%d' % (host, PORT)

    def __enter__(self):
        self.proc = Popen(
            [sys.executable, '-u', '-m', 'tests.mockserver', self.resource],
            stdout=PIPE)
        self.proc.stdout.readline()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.proc.kill()
        self.proc.wait()
        time.sleep(0.2)


PORT = 8781


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('resource')
    args = parser.parse_args()
    module_name, name = args.resource.rsplit('.', 1)
    sys.path.append('.')
    resource = getattr(import_module(module_name), name)()
    http_port = reactor.listenTCP(PORT, Site(resource))
    def print_listening():
        host = http_port.getHost()
        print('Mock server {} running at http://{}:{}'.format(
            resource, host.host, host.port))
    reactor.callWhenRunning(print_listening)
    reactor.run()


if __name__ == "__main__":
    main()
