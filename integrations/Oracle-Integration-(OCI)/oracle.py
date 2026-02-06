#!/var/ossec/framework/python/bin/python3

import logging
import sys
import json
import exceptions
import tools
from datetime import datetime, timedelta, timezone
from socket import AF_UNIX, SOCK_DGRAM, socket, error as socket_error
import oci
from os import path
sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
from utils import ANALYSISD, MAX_EVENT_SIZE
from base64 import b64decode

SOCKET_HEADER = '1:Oracle:'
DATETIME_MASK = '%Y-%m-%dT%H:%M:%S.%fZ'

# === Consumer Group Parameters ===
# Unique group name for OCI Streaming consumer group.
# Change this value to restart consumption from the beginning.
GROUP_NAME = "group1"
# Unique instance name for this consumer. Should be unique per client.
# Change this value to treat this as a new instance.
INSTANCE_NAME = "group1-instance1"

# Logger parameters
LOGGING_MSG_FORMAT = '%(asctime)s oracle: %(levelname)s: %(message)s'
LOGGING_DATE_FORMAT = '%Y/%m/%d %H:%M:%S'

# Global variable for output path
OUTPUT_PATH = None

logging.basicConfig(format=LOGGING_MSG_FORMAT, datefmt=LOGGING_DATE_FORMAT)
logger = logging.getLogger()

def get_logger(log_level):
    logger.setLevel(log_level)
    return logger


def create_group_cursor(stream_client, stream_id, group_name, instance_name, type="TRIM_HORIZON"):
    """
    Create a group cursor for accessing the stream.
    - group_name: Unique name for the consumer group. Change to restart from beginning.
    - instance_name: Unique identifier for this consumer process.
    - type: 'TRIM_HORIZON' starts from the oldest available message.
    """
    try:
        logger.debug(f"Creating cursor with type: {type} for group: {group_name}, instance: {instance_name}")
        
        cursor_details = oci.streaming.models.CreateGroupCursorDetails(
            group_name=group_name,
            instance_name=instance_name,
            type=getattr(oci.streaming.models.CreateGroupCursorDetails, f"TYPE_{type.upper()}"),
            commit_on_get=True  # Ensures OCI remembers the offset for this group/instance
        )
        
        logger.debug(f"Cursor details created: {cursor_details}")
        
        cursor = stream_client.create_group_cursor(
            stream_id,
            cursor_details
        ).data.value

        logger.info(f"Group cursor created successfully for group '{group_name}', instance '{instance_name}', type '{type}'")
        logger.debug(f"Generated cursor value: {cursor}")
        return cursor
    except Exception as e:
        logger.error(f"Error creating group cursor for stream {stream_id}: {e}")
        logger.debug(f"Failed cursor details - group: {group_name}, instance: {instance_name}, type: {type}")
        raise

def get_stream_messages(stream_client, stream_id, cursor):
    """Fetch messages from an Oracle Cloud Stream."""
    try:
        messages = stream_client.get_messages(
            stream_id=stream_id,
            cursor=cursor
        ).data

        logger.info(f"Fetched {len(messages)} messages from the stream.")
        return messages
    except Exception as e:
        logger.error(f"Error fetching messages from stream: {e}")
        return []

def process_stream_messages_group(stream_client, stream_id, logger, group_name, instance_name):
    """Process messages using a consumer group (remembers last position)."""
    cursor = create_group_cursor(
        stream_client,
        stream_id,
        group_name=group_name,
        instance_name=instance_name,
        type="TRIM_HORIZON"  # Starts from the oldest available message for new groups
    )

    logger.debug(f"Processing stream messages with group '{group_name}' and instance '{instance_name}'")

    num_processed_messages = 0
    
    # Loop continuo como en el script que funciona
    while True:
        get_response = stream_client.get_messages(stream_id, cursor, limit=250)
        
        if not get_response.data:
            logger.info("No more messages available")
            break
            
        messages = get_response.data
        logger.info(f"Fetched {len(messages)} messages from the stream.")

        for message in messages:
            try:
                event = b64decode(message.value.encode()).decode()
                event_json = json.loads(event)
                logger.debug('event details {}'.format(json.dumps(event_json)))
                
                # Send message either to file or analysisd based on OUTPUT_PATH
                if OUTPUT_PATH:
                    write_to_file(event_json)
                else:
                    send_message(event_json)
                
                num_processed_messages += 1
            except exceptions.WazuhIntegrationInternalError as e:
                logger.error(f"Wazuh integration error: {e}")
            except Exception as e:
                logger.error(f"Error processing stream message: {e}")
        
        # CLAVE: Actualizar cursor para el siguiente batch
        cursor = get_response.headers["opc-next-cursor"]

    logger.info(f"Successfully processed and acknowledged {num_processed_messages} messages")

def write_to_file(message):
    """Write message to local file."""
    try:
        logger.debug(f"Attempting to write message to file: {OUTPUT_PATH}")
        
        with open(OUTPUT_PATH, 'a', encoding='utf-8') as f:
            # Write the message as JSON with timestamp
            timestamp = datetime.now(timezone.utc).strftime(DATETIME_MASK)
            event_with_timestamp = {
                'timestamp': timestamp,
                'event': message
            }
            f.write(json.dumps(event_with_timestamp) + '\n')
            logger.debug(f"Message successfully written to file: {OUTPUT_PATH}")
    except IOError as e:
        logger.error(f"I/O error writing message to file {OUTPUT_PATH}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error writing message to file {OUTPUT_PATH}: {e}")
        logger.debug(f"Message content: {message}", exc_info=True)
        raise

def send_message(message):
    """Send a message with a header to the analysisd queue."""
    s = socket(AF_UNIX, SOCK_DGRAM)
    encoded_msg = f'{SOCKET_HEADER}{json.dumps(message)}'.encode(errors='replace')
    
    logger.debug(f"Preparing message for analysisd. Size: {len(encoded_msg)} bytes")
    
    if len(encoded_msg) > MAX_EVENT_SIZE:
        logger.warning(f'WARNING: Event size ({len(encoded_msg)} bytes) exceeds maximum allowed limit of {MAX_EVENT_SIZE} bytes')
    
    try:
        logger.debug(f"Connecting to analysisd socket: {ANALYSISD}")
        s.connect(ANALYSISD)
        s.send(encoded_msg)
        logger.debug("Message successfully sent to analysisd")
    except socket_error as e:
        if e.errno == 111:
            logger.error('ERROR: Wazuh must be running. Connection refused to analysisd socket')
            sys.exit(1)
        elif e.errno == 90:
            logger.error(f'ERROR: Message too long to send to Wazuh ({len(encoded_msg)} bytes). Skipping message...')
        else:
            logger.error(f'ERROR: Socket error sending message to Wazuh (errno {e.errno}): {e}')
            logger.debug(f"Socket path: {ANALYSISD}, Message size: {len(encoded_msg)}")
            sys.exit(1)
    except Exception as e:
        logger.error(f'ERROR: Unexpected error sending message to Wazuh: {e}')
        logger.debug(f"Message content: {json.dumps(message)}", exc_info=True)
        sys.exit(1)
    finally:
        s.close()

def main():
    global OUTPUT_PATH
    
    try:
        arguments = tools.get_script_arguments()
        logger = get_logger(arguments.log_level)
        
        # Set the global OUTPUT_PATH variable
        OUTPUT_PATH = arguments.output_path
        
        if OUTPUT_PATH:
            logger.info(f"Events will be written to local file: {OUTPUT_PATH}")
        else:
            logger.info("Events will be sent to analysisd")

        config = oci.config.from_file(arguments.credentials_file, "DEFAULT")

        stream_client = oci.streaming.StreamClient(config, service_endpoint=config["service_endpoint"])

        # Debug log for group and instance info
        logger.debug(f"Using OCI Streaming consumer group: '{GROUP_NAME}', instance: '{INSTANCE_NAME}'")

        logger.info(f"Fetching messages from stream ID: {arguments.stream_id} using consumer group.")
        process_stream_messages_group(
            stream_client,
            arguments.stream_id,
            logger,
            GROUP_NAME,
            INSTANCE_NAME
        )
    except Exception as e:
        logger.debug(f'Unknown error: {e}', exc_info=True)
        exit(1)
    else:
        exit(0)

if __name__ == "__main__":
    main()
