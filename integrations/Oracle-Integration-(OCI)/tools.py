#!/usr/bin/env python3

import argparse
import logging
from sys import stdout
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pytz import UTC


logger_name = ':oracle_wodle:'
logger = logging.getLogger(logger_name)
logging_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')


def get_script_arguments():
    """Get script arguments"""
    parser = argparse.ArgumentParser(
        usage="usage: %(prog)s [options]",
        description="Wazuh wodle for monitoring Oracle Cloud Stream",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        '-sid', '--streamid', dest='stream_id',
        help='Stream ID: identifier for the Oracle Cloud stream to fetch messages from.',
        required=True
    )

    parser.add_argument(
        '-c', '--credentials_file', dest='credentials_file',
        help='Path to credentials file',
        required=True
    )

    parser.add_argument(
        '-l', '--log_level', dest='log_level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Log level (default: INFO). Choose one of DEBUG, INFO, WARNING, ERROR.'
    )

    parser.add_argument(
        '-p', '--path', dest='output_path',
        help='Path to local file for writing events. If not specified, events will be sent to analysisd.',
        required=False,
        default=None
    )

    return parser.parse_args()


def get_stdout_logger(name: str, level: int = 0) -> logging.Logger:
    """Create a logger which returns the messages by stdout"""
    logger_stdout = logging.getLogger(name)
    # set log level
    logger.setLevel(log_levels.get(level, logging.WARNING))
    # set handler for stdout
    stdout_handler = logging.StreamHandler(stdout)
    stdout_handler.setFormatter(logging_format)
    logger_stdout.addHandler(stdout_handler)

    return logger_stdout


def arg_valid_date(arg_string: str) -> datetime:
    """Validation function for only_logs_after dates.

    Parameters
    ----------
    arg_string : str
        The only_logs_after value in YYYY-MMM-DD format.

    Returns
    -------
    datetime
        The date corresponding to the string passed.

    Raises
    ------
    ValueError
        If the parameter passed is not in the expected format.
    """
    try:
        return datetime.strptime(arg_string, "%Y-%b-%d").replace(tzinfo=UTC)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Argument not a valid date in format YYYY-MMM-DD: '{arg_string}'.")
