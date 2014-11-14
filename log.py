#!/usr/bin/env python

import argparse
import pickle
import datetime
import struct
import sys
import ssl
import socket
import urllib2
import base64
import time
import logging
import subprocess
import re

parser = argparse.ArgumentParser(
  description="Record and submit network performance data to graphite",
  formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--timeout', type=int, default=300,
                    help="TCP and HTTP timeout [seconds]")
parser.add_argument('--log_level', type=lambda s: getattr(logging, s),
                    default=logging.WARNING,
                    help="Verbosity [DEBUG|INFO|WARNING]")
parser.add_argument('--graphite', type=str, required=True,
                    help="Graphite server to use [IP|hostname]")
parser.add_argument('--graphite_port', type=int, default=2004,
                    help="Port of graphite server [1-65535]")
parser.add_argument('--period',
                    type=lambda s: datetime.timedelta(seconds=int(s)),
                    default=datetime.timedelta(minutes=1),
                    help="Frequency of recording data [seconds]")
parser.add_argument('--server', type=str, nargs=2, action='append',
                    metavar=('NAME', 'HOST'), required=True,
                    help="servers to connect to [IP|hostname]")
parser.add_argument('--sock_port', type=int, action='append', default=(80,),
                    help="Ports for test sockets [1-65535]")
parser.add_argument('--ssl_port', type=int, action='append', default=(443,),
                    help="Ports for test SSL sockets [1-65535]")
parser.add_argument('--scheme', type=str, action='append', default=('https',),
                    help="HTTP scheme [http|https]")
parser.add_argument('--host', type=str, default=None,
                    help="HTTP Host header [hostname]")
parser.add_argument('--user', type=str, default=None,
                    help="HTTP Authorization credentials [user:password]")
parser.add_argument('--path', type=str, default="/",
                    help="HTTP path to request [/path/to/resource]")
parser.add_argument('--ping', default=False, action='store_true',
                    help="Run a ping test")
parser.add_argument('identifier',
                    help="A unique identifier for this host [string]")

logger = logging.getLogger(__name__)

class Metrics(object):
  def __init__(self, metrics=None):
    self.metrics = metrics or list()

  def Add(self, param, value, time):
    self.metrics.append((param,
                         ((time - datetime.datetime(1970,1,1)).total_seconds(),
                         value)))

  def __add__(self, other):
    return Metrics(self.metrics + other.metrics)

  def __repr__(self):
    return "Metrics(%r)" % (self.metrics)

  def Serialize(self):
    payload = pickle.dumps(self.metrics, protocol=2)
    header = struct.pack("!L", len(payload))
    return header + payload

  def Prefixed(self, *prefixes):
    prefix_str = "".join("%s." % prefix for prefix in prefixes)
    return Metrics([
        (prefix_str+m[0], m[1]) for m in self.metrics])


def SendMetrics(metrics, graphite_server):
  logger.info('sending metrics to %s:%d', *graphite_server)
  logger.debug('metrics: %r', metrics)
  serialized_metrics = metrics.Serialize()
  logger.debug('serialized as: %r', serialized_metrics)
  sock = socket.create_connection(graphite_server)
  sock.sendall(serialized_metrics)
  sock.close()


def GatherServerSocketMetrics(args, server, port, do_ssl=False):
  metrics = Metrics()
  start = datetime.datetime.utcnow()
  logger.info('Trying TCP connect to %s:%d', server[1], port)
  try:
    sock = socket.create_connection((server[1], port), args.timeout)
  except socket.timeout as e:
    logger.warning('Timeout', exc_info=True)
    metrics.Add('timeout', 1, start)
    return metrics.Prefixed(server[0], port)
  except socket.error as e:
    logger.error('Failed', exc_info=True)
    metrics.Add('errors', 1, start)
    return metrics.Prefixed(server[0], port)
  metrics.Add('connect_time',
              (datetime.datetime.utcnow() - start).total_seconds(), start)
  if do_ssl:
    logger.info('Trying SSL handshake')
    try:
      ssl_sock = ssl.wrap_socket(sock)
    except ssl.SSLError:
      pass
    metrics.Add('ssl_handshake_time',
                (datetime.datetime.utcnow() - start).total_seconds(), start)
    metrics.Add('ssl_cert_length', len(ssl_sock.getpeercert(True)), start)
  sock.close()
  return metrics.Prefixed(server[0], port)


def GatherServerHttpMetrics(args, schema, server):
  metrics = Metrics()
  start = datetime.datetime.utcnow()
  request = urllib2.Request(url='%s://%s%s' % (schema, server[1], args.path))
  if args.host:
    request.add_header('Host', args.host)
  if args.user:
    request.add_header('Authorization', 'Basic %s' %
                       base64.b64encode(args.user))
  logger.info('Requesting %s', request.get_full_url())
  try:
    response = urllib2.urlopen(request, timeout=args.timeout)
    logger.debug('Response: %d %s\n%s', response.code, response.msg,
                 response.headers)
  except urllib2.HTTPError as e:
    # HTTPError can be used just like response
    logger.warning('HTTP Error', exc_info=True)
    response = e
    metrics.Add('errors', 1, start)
  except urllib2.URLError as e:
    metrics.Add('errors', 1, start)
    if isinstance(e.reason, socket.timeout):
      logger.warning('Timeout', exc_info=True)
      metrics.Add('timeout', 1, start)
    else:
      metrics.Add('errors', 1, start)
      logger.error('Failed', exc_info=True)
    return metrics.Prefixed(server[0], schema)
  size = len(response.read(1))
  metrics.Add('time_to_first_byte',
              (datetime.datetime.utcnow() - start).total_seconds(), start)
  size += len(response.read())
  metrics.Add('time_to_last_byte',
              (datetime.datetime.utcnow() - start).total_seconds(), start)
  metrics.Add('code', response.getcode(), start)
  metrics.Add('size', size, start)
  return metrics.Prefixed(server[0], schema)

def GatherPingMetrics(args, server):
  metrics = Metrics()
  start = datetime.datetime.utcnow()
  logger.info('Pinging %s', server[1])
  try:
    output = subprocess.check_output(["ping" , "-c", "1", "-w",
                                      str(args.timeout), "-q", server[1]])
  except subprocess.CalledProcessError as e:
    if e.returncode == 1:
      logger.warning('Timeout', exc_info=True)
      metrics.Add('timeout', 1, start)
    else:
      metrics.Add('errors', 1, start)
      logger.error('Failed', exc_info=True)
  else:
    match = re.search(
      r'rtt min/avg/max/mdev = (?P<min>[\d.]*)/(?P<avg>[\d.]*)/(?P<max>[\d.]*)/(?P<mdev>[\d.]*) ms',
      output)
    for m, v in match.groupdict().items():
      metrics.Add(m, v, start)
  return metrics.Prefixed(server[0], 'ping')

def GatherAllMetrics(args):
  http_metrics = reduce(
    lambda a, b: a+b,
    (GatherServerHttpMetrics(args, schema, server)
     for schema in args.scheme for server in args.server))
  socket_metrics = reduce(
    lambda a, b: a+b,
    (GatherServerSocketMetrics(args, server, port)
     for port in args.sock_port for server in args.server))
  ssl_metrics = reduce(
    lambda a, b: a+b,
    (GatherServerSocketMetrics(args, server, port, True)
     for port in args.ssl_port for server in args.server))
  if args.ping:
    ping_metrics = reduce(
      lambda a, b: a+b,
      (GatherPingMetrics(args, server)
       for server in args.server))
    return http_metrics+socket_metrics+ssl_metrics+ping_metrics
  return http_metrics+socket_metrics+ssl_metrics


def LoopOnce(args):
  metrics = GatherAllMetrics(args).Prefixed('loga', args.identifier)
  SendMetrics(metrics, (args.graphite,args.graphite_port))


def MainLoop(args):
  last_time = datetime.datetime.utcnow()
  while True:
    next_time = last_time + args.period
    LoopOnce(args)
    last_time = datetime.datetime.utcnow()
    if last_time < next_time:
      time.sleep((next_time-last_time).total_seconds())
    else:
      logger.error('Data collection took longer than update period: %s > %s',
                     last_time-next_time+args.period, args.period)
    last_time = next_time


if __name__ == '__main__':
  args = parser.parse_args()
  logging.basicConfig(format='%(asctime)s %(message)s', level=args.log_level)
  MainLoop(args)
