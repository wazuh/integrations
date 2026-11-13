#!/var/ossec/framework/python/bin/python3
"""Forward Oracle Cloud Infrastructure (OCI) logs into Wazuh.

OCI has no native Wazuh wodle. The supported path is:

    OCI service  ->  Logging (+ Audit)  ->  Connector Hub  ->  Streaming
                                                            \\-> Object Storage

This script is the last hop: it reads the log records Connector Hub delivered
to a stream or a bucket, normalises them, and hands them to Wazuh -- either
straight to analysisd's socket or as JSON lines on disk for a <localfile>
block to tail.

Sources:
    streaming       poll an OCI Streaming stream using a consumer group
    objectstorage   poll an Object Storage bucket, checkpointing by object name
    local           replay a file of OCI records (offline testing, no tenancy)

Outputs:
    analysisd       datagram to the Wazuh queue socket, header "1:oci:"
    file            newline-delimited JSON for <localfile><log_format>json
    stdout          print, for piping into wazuh-logtest
"""

import argparse
import gzip
import json
import logging
import os
import sys
from base64 import b64decode
from datetime import datetime, timezone
from socket import AF_UNIX, SOCK_DGRAM, SOL_SOCKET, SO_SNDBUF, socket
from socket import error as socket_error

try:
    import oci
except ImportError:  # only 'local' source works without the SDK
    oci = None

SOCKET_HEADER = '1:oci:'
# analysisd drops datagrams larger than this.
MAX_EVENT_SIZE = 65535
DEFAULT_STATE_FILE = '/var/ossec/var/run/oci-logs.state'

LOGGING_MSG_FORMAT = '%(asctime)s oci-logs: %(levelname)s: %(message)s'
LOGGING_DATE_FORMAT = '%Y/%m/%d %H:%M:%S'

logger = logging.getLogger('oci-logs')


# --------------------------------------------------------------------------
# Wazuh paths
# --------------------------------------------------------------------------

def find_wazuh_path() -> str:
    """Walk up from this file to the Wazuh root, or fall back to /var/ossec."""
    parts = os.path.abspath(os.path.dirname(__file__)).split(os.sep)
    for anchor in ('wodles', 'integrations'):
        if anchor in parts:
            return os.sep.join(parts[:parts.index(anchor)]) or os.sep
    return '/var/ossec'


ANALYSISD = os.path.join(find_wazuh_path(), 'queue', 'sockets', 'queue')


# --------------------------------------------------------------------------
# Record normalisation
# --------------------------------------------------------------------------

# Service-log types, longest prefix first. Audit records are detected by shape
# below because their types collide with these (both start com.oraclecloud.*).
SERVICE_LOG_TYPES = (
    ('com.oraclecloud.vcn.flowlogs', 'vcn_flow'),
    ('com.oraclecloud.apigateway.access', 'apigateway_access'),
    ('com.oraclecloud.apigateway.execution', 'apigateway_execution'),
    ('com.oraclecloud.objectstorage', 'objectstorage'),
    ('com.oraclecloud.emaildelivery', 'emaildelivery'),
    ('com.oraclecloud.dataintegration', 'data_integration'),
    ('com.oraclecloud.integration', 'integration_service'),
    ('com.oraclecloud.loadbalancer', 'loadbalancer'),
    ('com.oraclecloud.waf', 'waf'),
    ('com.oraclecloud.functions', 'functions'),
    ('com.oraclecloud.oke', 'oke'),
    ('com.oraclecloud.database', 'database'),
    ('com.oraclecloud.autonomousdatabase', 'database'),
)

# Where to look for a value, in order, when hoisting normalised fields.
SEARCH_PATHS = ((), ('identity',), ('request',), ('response',))

FIELD_ALIASES = (
    ('srcip', ('sourceAddress', 'clientIp', 'clientIpAddress', 'sourceIp',
               'srcaddr', 'remoteAddress', 'senderIp', 'ipAddress')),
    ('dstip', ('destinationAddress', 'dstaddr', 'targetAddress')),
    ('srcport', ('sourcePort', 'srcport')),
    ('dstport', ('destinationPort', 'dstport')),
    ('srcuser', ('principalName', 'userName', 'sender', 'principalId')),
    ('dstuser', ('recipient',)),
    ('action', ('action', 'httpMethod', 'method', 'operation')),
    ('status', ('status', 'responseStatus', 'statusCode', 'httpStatusCode')),
    ('url', ('path', 'requestUri', 'requestPath', 'uri', 'url')),
    ('protocol', ('protocolName', 'protocol')),
)

# Envelope keys carrying resource context, mapped to friendlier names. OCI
# lowercases these inside logContent.oracle.
ORACLE_KEYS = (
    ('compartmentid', 'compartment_id'),
    ('compartmentname', 'compartment_name'),
    ('loggroupid', 'log_group_id'),
    ('logid', 'log_id'),
    ('tenantid', 'tenant_id'),
    ('ingestedtime', 'ingested_time'),
    ('subnetocid', 'subnet_id'),
    ('vnicocid', 'vnic_id'),
    ('vniccompartmentocid', 'vnic_compartment_id'),
    ('instanceocid', 'instance_id'),
)


def _dig(obj, *keys):
    """Fetch a nested key path, returning None instead of raising."""
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def unwrap(record: dict) -> dict:
    """Strip the Logging envelope. Object Storage delivery keeps records under
    'logContent'; Streaming delivery usually does not."""
    inner = record.get('logContent')
    return inner if isinstance(inner, dict) else record


def classify(record: dict) -> tuple:
    """Return (log_type, service) for an OCI log record."""
    data = record.get('data')
    data = data if isinstance(data, dict) else {}
    event_type = (record.get('type') or record.get('eventType') or '')
    source = record.get('source') or ''
    if source == '-':  # flow logs use '-' as a placeholder source
        source = ''

    segments = event_type.split('.')

    # Audit records always carry both an eventName and an identity block.
    if 'eventName' in data and 'identity' in data:
        # com.oraclecloud.<service>.<Operation> -> <service>
        return 'audit', source or (segments[2] if len(segments) > 3 else '')

    lowered = event_type.lower()
    for prefix, log_type in SERVICE_LOG_TYPES:
        if lowered.startswith(prefix):
            return log_type, source or prefix.split('.')[2]

    return 'oci', source or (segments[2] if len(segments) > 2 else '')


def hoist(record: dict, log_type: str) -> dict:
    """Lift a handful of values to top-level Wazuh field names so rules and the
    alert schema can use srcip/srcuser/action/status directly."""
    data = record.get('data')
    data = data if isinstance(data, dict) else {}
    out = {}

    for field, aliases in FIELD_ALIASES:
        for path in SEARCH_PATHS:
            scope = _dig(data, *path) if path else data
            if not isinstance(scope, dict):
                continue
            for alias in aliases:
                value = scope.get(alias)
                if value not in (None, '', [], {}):
                    out[field] = value if isinstance(value, str) else str(value)
                    break
            if field in out:
                break

    # For audit, the operation name is far more useful than the HTTP verb.
    if log_type == 'audit' and data.get('eventName'):
        out['action'] = data['eventName']

    return out


def normalise(raw: dict) -> dict:
    """Turn one OCI log record into the event Wazuh receives."""
    record = unwrap(raw)
    log_type, service = classify(record)
    oracle = record.get('oracle')
    oracle = oracle if isinstance(oracle, dict) else {}

    oci_block = {
        'log_type': log_type,
        'service': service,
        'type': record.get('type') or record.get('eventType') or '',
        'time': record.get('time') or record.get('eventTime') or '',
        'id': record.get('id') or record.get('eventId') or '',
        'data': record.get('data'),
    }
    for source_key, dest_key in ORACLE_KEYS:
        if oracle.get(source_key):
            oci_block[dest_key] = oracle[source_key]

    # Audit carries compartment on the payload rather than the envelope.
    data = record.get('data')
    if isinstance(data, dict):
        oci_block.setdefault('compartment_id', data.get('compartmentId') or '')
        oci_block.setdefault('compartment_name', data.get('compartmentName') or '')
        if data.get('resourceName'):
            oci_block['resource_name'] = data['resourceName']
        if data.get('resourceId'):
            oci_block['resource_id'] = data['resourceId']
    oci_block = {k: v for k, v in oci_block.items() if v not in (None, '')}

    # Emitted twice on purpose. At the top level these land on Wazuh's *static*
    # decoder fields, which is what populates srcip/srcuser/status in the alert
    # schema and what <same_source_ip/> keys on. But analysisd matches static
    # fields with strcmp (<action>) or OSMatch (<status>), so neither supports
    # the regex the rules need. The mirror under oci.* is dynamic, and <field>
    # on a dynamic name gets full OS_Regex.
    hoisted = hoist(record, log_type)
    oci_block.update(hoisted)
    # Rules gate on oci.status with negate="yes", which does not match when the
    # field is absent. Always emitting it keeps records that carry no status
    # from falling out of the ruleset. Only the mirror gets the placeholder --
    # the top-level static field stays empty so the alert schema shows no
    # status rather than a fabricated one.
    oci_block.setdefault('status', 'unknown')

    event = {'integration': 'oci', 'oci': oci_block}
    event.update(hoisted)
    return event


def parse_payload(payload: bytes):
    """Yield records from a Connector Hub payload.

    Handles gzip or plain, and either a JSON array/object or newline-delimited
    JSON -- Connector Hub has used both shapes depending on target and version.
    """
    if payload[:2] == b'\x1f\x8b':
        payload = gzip.decompress(payload)
    text = payload.decode('utf-8', errors='replace').strip()
    if not text:
        return

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        pass
    else:
        for item in (parsed if isinstance(parsed, list) else [parsed]):
            if isinstance(item, dict):
                yield item
        return

    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as err:
            logger.warning('Skipping unparseable line %d: %s', line_no, err)
            continue
        if isinstance(item, dict):
            yield item


# --------------------------------------------------------------------------
# Outputs
# --------------------------------------------------------------------------

class Output:
    """Where normalised events go."""

    def __init__(self, mode: str, path: str = None):
        self.mode = mode
        self.path = path
        self._sock = None
        self._fh = None
        self.sent = 0

        if mode == 'file':
            if not path:
                raise ValueError('--output file requires --path')
            directory = os.path.dirname(os.path.abspath(path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            self._fh = open(path, 'a', encoding='utf-8')

    def _connect(self):
        if self._sock is not None:
            return
        if not os.path.exists(ANALYSISD):
            logger.error('Wazuh queue socket not found at %s. Is the manager '
                         'running, or did you mean --output file?', ANALYSISD)
            sys.exit(1)
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.setsockopt(SOL_SOCKET, SO_SNDBUF, MAX_EVENT_SIZE)
        sock.connect(ANALYSISD)
        self._sock = sock

    def send(self, event: dict):
        body = json.dumps(event)
        if self.mode == 'analysisd':
            body = self._fit(event, body)
            self._connect()
            try:
                self._sock.send(f'{SOCKET_HEADER}{body}'.encode(errors='replace'))
            except socket_error as err:
                logger.error('Socket error sending to analysisd: %s', err)
                self._sock.close()
                self._sock = None
                raise
        elif self.mode == 'file':
            self._fh.write(body + '\n')
        else:
            print(body)
        self.sent += 1

    def _fit(self, event: dict, body: str) -> str:
        """Drop the raw payload rather than lose an oversized event entirely."""
        if len(body) + len(SOCKET_HEADER) <= MAX_EVENT_SIZE:
            return body
        logger.warning('Event of %d bytes exceeds the %d byte analysisd limit; '
                       'dropping oci.data', len(body), MAX_EVENT_SIZE)
        trimmed = dict(event)
        trimmed['oci'] = {k: v for k, v in event['oci'].items() if k != 'data'}
        trimmed['oci']['truncated'] = True
        return json.dumps(trimmed)

    def close(self):
        if self._sock is not None:
            self._sock.close()
        if self._fh is not None:
            self._fh.close()


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

def load_state(path: str) -> dict:
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as err:
        logger.warning('Ignoring unreadable state file %s: %s', path, err)
        return {}


def save_state(path: str, state: dict):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f'{path}.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(state, handle)
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def build_auth(args):
    """Return (config, signer). signer is None for plain API-key auth."""
    if oci is None:
        logger.error("The 'oci' Python SDK is not installed. "
                     'Run: pip install -r requirements.txt')
        sys.exit(1)

    if args.auth == 'instance_principal':
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        return {'region': args.region or signer.region}, signer

    if args.auth == 'resource_principal':
        signer = oci.auth.signers.get_resource_principals_signer()
        return {'region': args.region or signer.region}, signer

    config = oci.config.from_file(args.config_file, args.profile)
    if args.region:
        config['region'] = args.region
    oci.config.validate_config(config)
    return config, None


def make_client(client_class, config, signer, **kwargs):
    if signer is not None:
        return client_class(config, signer=signer, **kwargs)
    return client_class(config, **kwargs)


# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------

def run_streaming(args, output, config, signer):
    """Consume a stream via a consumer group. OCI tracks the offset server-side,
    so restarts resume where the previous run stopped."""
    endpoint = args.stream_endpoint
    if not endpoint:
        admin = make_client(oci.streaming.StreamAdminClient, config, signer)
        endpoint = admin.get_stream(args.stream_id).data.messages_endpoint
        logger.debug('Resolved messages endpoint: %s', endpoint)

    client = make_client(oci.streaming.StreamClient, config, signer,
                         service_endpoint=endpoint)

    cursor = client.create_group_cursor(
        args.stream_id,
        oci.streaming.models.CreateGroupCursorDetails(
            group_name=args.group_name,
            instance_name=args.instance_name,
            type=getattr(oci.streaming.models.CreateGroupCursorDetails,
                         f'TYPE_{args.cursor_type.upper()}'),
            commit_on_get=True,
        ),
    ).data.value
    logger.info("Consuming stream %s as group '%s' instance '%s'",
                args.stream_id, args.group_name, args.instance_name)

    empty_polls = 0
    while True:
        response = client.get_messages(args.stream_id, cursor, limit=args.limit)
        messages = response.data or []

        if not messages:
            empty_polls += 1
            if empty_polls >= args.empty_polls:
                logger.info('Stream drained after %d empty polls', empty_polls)
                break
        else:
            empty_polls = 0

        for message in messages:
            try:
                payload = b64decode(message.value)
            except Exception as err:
                logger.warning('Skipping message with undecodable value: %s', err)
                continue
            for record in parse_payload(payload):
                output.send(normalise(record))

        cursor = response.headers['opc-next-cursor']
        if args.max_records and output.sent >= args.max_records:
            logger.info('Reached --max-records (%d)', args.max_records)
            break


def run_objectstorage(args, output, config, signer):
    """Walk the bucket in name order, checkpointing the last object read.

    Connector Hub writes objects under a time-ordered key prefix, so lexical
    order is chronological and a name checkpoint is enough to resume.
    """
    client = make_client(oci.object_storage.ObjectStorageClient, config, signer)
    namespace = args.namespace or client.get_namespace().data
    logger.debug('Object Storage namespace: %s', namespace)

    state = load_state(args.state_file)
    key = f'objectstorage:{namespace}/{args.bucket}/{args.prefix or ""}'
    last_object = state.get(key, {}).get('last_object')
    if last_object:
        logger.info('Resuming after object %s', last_object)

    start = last_object
    processed = 0
    while True:
        listing = client.list_objects(
            namespace, args.bucket,
            prefix=args.prefix or None,
            start=start,
            limit=min(args.limit, 1000),
            fields='name,timeCreated,size',
        ).data

        summaries = [obj for obj in listing.objects if obj.name != last_object]
        for summary in summaries:
            if args.start_time and summary.time_created and \
                    summary.time_created < args.start_time:
                logger.debug('Skipping %s (older than --start-time)', summary.name)
                last_object = summary.name
                continue

            logger.debug('Reading %s (%s bytes)', summary.name, summary.size)
            payload = client.get_object(namespace, args.bucket, summary.name).data.content
            for record in parse_payload(payload):
                output.send(normalise(record))

            last_object = summary.name
            processed += 1
            state[key] = {
                'last_object': last_object,
                'updated': datetime.now(timezone.utc).isoformat(),
            }
            save_state(args.state_file, state)

            if args.delete_after_read:
                client.delete_object(namespace, args.bucket, summary.name)
                logger.debug('Deleted %s', summary.name)

            if args.max_records and output.sent >= args.max_records:
                logger.info('Reached --max-records (%d)', args.max_records)
                return

        if not listing.next_start_with:
            break
        start = listing.next_start_with

    logger.info('Processed %d object(s)', processed)


def run_local(args, output, _config=None, _signer=None):
    """Replay records from a local file. No tenancy or SDK required."""
    with open(args.input, 'rb') as handle:
        payload = handle.read()
    for record in parse_payload(payload):
        output.send(normalise(record))
        if args.max_records and output.sent >= args.max_records:
            break


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def valid_datetime(value: str) -> datetime:
    for mask in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(value, mask).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"'{value}' is not YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")


def get_arguments(argv=None):
    parser = argparse.ArgumentParser(
        description='Forward OCI logs collected by Connector Hub into Wazuh.',
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-s', '--source', required=True,
                        choices=['streaming', 'objectstorage', 'local'],
                        help='Where Connector Hub delivered the logs.')

    auth = parser.add_argument_group('authentication')
    auth.add_argument('--auth', default='config',
                      choices=['config', 'instance_principal', 'resource_principal'],
                      help='config: API key file (default). instance_principal:\n'
                           'no keys, for an OCI compute instance in a dynamic group.')
    auth.add_argument('-c', '--config-file', default='~/.oci/config',
                      help='OCI config file (default: ~/.oci/config).')
    auth.add_argument('-p', '--profile', default='DEFAULT',
                      help='Profile within the config file (default: DEFAULT).')
    auth.add_argument('--region', help='Override the region from the config.')

    stream = parser.add_argument_group('streaming source')
    stream.add_argument('--stream-id', help='OCID of the stream.')
    stream.add_argument('--stream-endpoint',
                        help='Messages endpoint. Looked up automatically if omitted.')
    stream.add_argument('--group-name', default='wazuh',
                        help='Consumer group. Change it to re-read from the start.')
    stream.add_argument('--instance-name', default='wazuh-1',
                        help='Consumer instance, unique per collector process.')
    stream.add_argument('--cursor-type', default='TRIM_HORIZON',
                        choices=['TRIM_HORIZON', 'LATEST'],
                        help='Where a brand new consumer group starts reading.')
    stream.add_argument('--empty-polls', type=int, default=2,
                        help='Consecutive empty polls before exiting (default: 2).')

    store = parser.add_argument_group('objectstorage source')
    store.add_argument('--namespace', help='Object Storage namespace (auto-detected).')
    store.add_argument('--bucket', help='Bucket receiving the Connector Hub output.')
    store.add_argument('--prefix', help='Object name prefix to restrict the listing.')
    store.add_argument('--start-time', type=valid_datetime,
                       help='Ignore objects created before this UTC time.')
    store.add_argument('--delete-after-read', action='store_true',
                       help='Delete each object once forwarded.')

    local = parser.add_argument_group('local source')
    local.add_argument('-i', '--input', help='File of OCI records to replay.')

    out = parser.add_argument_group('output')
    out.add_argument('-o', '--output', default='analysisd',
                     choices=['analysisd', 'file', 'stdout'],
                     help='analysisd: Wazuh queue socket (default).\n'
                          'file: JSON lines for a <localfile> block.')
    out.add_argument('--path', help='Destination file when --output file.')

    parser.add_argument('--state-file', default=DEFAULT_STATE_FILE,
                        help=f'Checkpoint file (default: {DEFAULT_STATE_FILE}).')
    parser.add_argument('--limit', type=int, default=250,
                        help='Records or objects fetched per request (default: 250).')
    parser.add_argument('--max-records', type=int, default=0,
                        help='Stop after this many events. 0 means no limit.')
    parser.add_argument('-l', '--log-level', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])

    args = parser.parse_args(argv)
    args.config_file = os.path.expanduser(args.config_file)

    required = {
        'streaming': [('stream_id', '--stream-id')],
        'objectstorage': [('bucket', '--bucket')],
        'local': [('input', '--input')],
    }[args.source]
    missing = [flag for attr, flag in required if not getattr(args, attr)]
    if missing:
        parser.error(f"--source {args.source} requires {', '.join(missing)}")

    return args


def main(argv=None) -> int:
    args = get_arguments(argv)
    logging.basicConfig(format=LOGGING_MSG_FORMAT, datefmt=LOGGING_DATE_FORMAT,
                        stream=sys.stderr)
    logger.setLevel(args.log_level)

    try:
        output = Output(args.output, args.path)
    except ValueError as err:
        logger.error('%s', err)
        return 1

    config, signer = (None, None)
    if args.source != 'local':
        config, signer = build_auth(args)

    runner = {'streaming': run_streaming,
              'objectstorage': run_objectstorage,
              'local': run_local}[args.source]

    try:
        runner(args, output, config, signer)
    except KeyboardInterrupt:
        logger.info('Interrupted')
    except Exception as err:
        logger.error('Collection failed: %s', err)
        logger.debug('Traceback', exc_info=True)
        return 1
    finally:
        logger.info('Forwarded %d event(s) via %s', output.sent, args.output)
        output.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
