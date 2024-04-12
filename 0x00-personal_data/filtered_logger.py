#!/usr/bin/env python3
"""
filtered_logger
"""
import os
import re
import logging
import mysql.connector
from typing import List


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Returns a connector to the database.
    """
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    connection = mysql.connector.connect(
            host=db_host,
            port=3306,
            user=db_user,
            password=db_pwd,
            database=db_name,
            )
    return connection


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str
        ) -> str:
    """
    Returns the log message obfuscated using regex substitution.
    """
    for field in fields:
        pattern = re.escape(field)
        message = re.sub(pattern, redaction, message)
    return message


def get_logger() -> logging.Logger:
    """
    Creates a new logger for user data.
    """
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Return formatted message
        """
        return filter_datum(
                self.fields,
                RedactingFormatter.REDACTION,
                record.msg,
                RedactingFormatter.SEPARATOR
                )


def main():
    """
    Main implementation
    """
    fields = ""
    columns = fields.splilt(",")
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))
            args = (
                    "user_data",
                    logging.INFO,
                    None,
                    None,
                    msg,
                    None,
                    None
                    )
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)
