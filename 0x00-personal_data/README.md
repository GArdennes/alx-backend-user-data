# 0x00. Personal data
## Learning Objectives
- Examples of Personally Identifiable Information (PII)
- How to implement a log filter that will obfuscate (**ob·​fus·​cate**) PII fields
- How to encrypt a password and check the validity of an input password
- How to authenticate to a database using environment variables

## Learning
Personally Identifiable Information (PII) is any data that can be used to identify a specific person. This can include direct identifiers like name, social security number, phone number, email address, or home address, indirect identifiers like date of birth, birthplace, gender, race, purchase history or internet browsing habits. PII is valuable because it can be used to target individuals for advertising, identity theft, or evade someone’s privacy.  PII is a subset of personal data (under GDPR), focusing on information that directly or indirectly reveals someone’s identity. An example of Personal data could be an IP address. Non-PII on the other hand exists outside the realm of PII but can become part of personal data if it can be used to identify someone for example age range, cookies or zip code.

#### **Here’s how to implement a log filter with the `logging` package to obfuscate PII fields.**
1. Define the PII fields: Identify the specific PII fields you want to anonymize in your logs.
2. Create a custom filter: We implement our obfuscation using a subclass of the logging package
```
import logging

class PIIFilter(logging.Filter):
  def __init__(self, pii_fields):
    self.pii_fields = pii_fields

  def filter(self, record):
    # Iterate through PII fields
    for field in self.pii_fields:
      # Check if the field exists in the record message
      if field in record.msg:
        # Replace the field value with a placeholder (e.g., '[REDACTED]')
        record.msg = record.msg.replace(getattr(record, field), '[REDACTED]')
    return True
```
3. Apply the filter to your logger: Here we demonstrate our custom filter with an example of a logging event.
```
import logging

# Define PII fields to obfuscate
pii_fields = ['name', 'email', 'phone_number']

# Create a filter instance
filter = PIIFilter(pii_fields)

# Get the logger and add the filter
logger = logging.getLogger(__name__)
logger.addFilter(filter)

# Configure logging (example: file logging)
logging.basicConfig(filename='app.log', level=logging.INFO)

# Example usage with PII
logger.info("Processing user data for user with name: John Doe, email: johndoe@example.com")
```

From this example, when the messages are logged containing the PII, the filter will replace those fields with the placeholder before writing them to the log file.


#### **Here is how to encrypt passwords and validate user input using the python bcrypt package.**
1. Hashing Passwords with BCrypt: Hashing refers to converting a string into a fixed-size hash using a hash function. BCrypt is a hashing algorithm that ensures security by producing a hash that doesn’t resemble the original input.

Here is an example:
```
import bcrypt

# Your plain-text password
password = "MySecretPassword"

# Encode the password into a readable utf-8 byte code
password_bytes = password.encode("utf-8")

# Generate a salt and hash the password
salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(password_bytes, salt)

print(f"Hashed password: {hashed_password.decode('utf-8')}")
```

2. Validating input passwords: You will need to compare the input password with the stored hashed password. You would use the `bcrypt.checkpw()` function to verify if the input password matches the stored hash.

Here is an example:
```
# Assume you have a stored hashed password (from a database, for example)
stored_hashed_password = b"$2b$12$...your_actual_hash_here..."

# User's input password
input_password = "MySecretPassword"

# Encode the input password
input_password_bytes = input_password.encode("utf-8")

# Check whether the literal-text password is valid for the stored hash
is_valid = bcrypt.checkpw(input_password_bytes, stored_hashed_password)

print(f"Is valid password? {is_valid}")  # Output: True
```

## Requirements
- All your files will be interpreted on Ubuntu 18.04 LTS using `python3`.
- All your files should end with a new line.
- The first line of all your files should be exactly `#!/usr/bin/env python3`
- A readme file, at the root of the folder of the project, is mandatory.
- Your code should use the `pycodestyle` style
- All your files must be executable.
- The length of your files will be tested using `wc`
- All your modules should have a documentation
- All your classes should have a documentation
- All your functions should have a documentation
- A documentation is not a simple word, it’s a real sentence explaining what’s the purpose of the module, class or method.
- All your functions should be type annotated.


## Tasks
### 0. Regex-ing
Write a function called `filter_datum(fields, redaction, message, separator)` that returns the log message obfuscated:

- `fields`: a list of strings representing all fields to obfuscate.
- `redaction`: a string representing what the field will be obfuscated.
- `message`: a string representing the log line
- `separator`: a string representation by which character is separating all fields in the log line(`message`)

**Requirements**
- The function should use a regex to replace occurrences of certain field values.
- `filter_datum` should be less than 5 lines long and use `re.sub` to perform the substitution with a single regex.

### 1. Log formatter
Copy the following code into `filtered_logger.py`.
```
import logging


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self):
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        NotImplementedError
```
Update the class to accept a list of strings `fields` constructor arguments. 

Implement the `format` method to filter values in incoming log records using `filter_datum`. 

Values for fields in `fields` should be filtered.

DO NOT extrapolate `FORMAT` manually. The `format` method should be less than 5 lines long.

```
bob@dylan:~$ cat main.py
#!/usr/bin/env python3
"""
Main file
"""

import logging
import re

RedactingFormatter = __import__('filtered_logger').RedactingFormatter

message = "name=Bob;email=bob@dylan.com;ssn=000-123-0000;password=bobby2019;"
log_record = logging.LogRecord("my_logger", logging.INFO, None, None, message, None, None)
formatter = RedactingFormatter(fields=("email", "ssn", "password"))
print(formatter.format(log_record))

bob@dylan:~$
bob@dylan:~$ ./main.py
[HOLBERTON] my_logger INFO 2019-11-19 18:24:25,105: name=Bob; email=***; ssn=***; password=***;
bob@dylan:~$
```

### 2. Create logger
Use [user_data.csv](https://intranet.alxswe.com/rltoken/cVQXXtttuAobcFjYFKZTow) for this task.

Implement a `get_logger` function that takes no arguments and returns a `logging.Logger` object.

The logger should be named `user_data` and only log up to `logging.INFO` level. It should not propagate messages to other loggers. It should have a `StreamHandler` with `RedactingFormatter` as formatter.

Create a tuple `PII_FIELDS` constant at the root of the module containing the fields from `user_data.csv` that are considered PII. `PII_FIELDS` can contain only 5 fields - choose the right list of fields that are considered as “important” PIIs or information that you **must hide** in your logs. Use it to parameterize the formattter.

### 3. Connect to secure database
Database credentials should NEVER be stored in code or checked into version control. One secure option is to store them as environment variables on the application server.

In this task, you will connect to a secure holberton database to read a users table. The database is protected by a username and password that are set as environment variables on the server named `PERSONAL_DATA_DB_USERNAME` (set the default as root), `PERSONAL_DATA_DB_PASSWORD` (set the default as an empty string) and `PERSONAL_DATA_DB_HOST` (set the default as localhost).

The database name is stored in `PERSONAL_DATA_DB_NAME`.

Implement a `get_db` function that returns a connector to the database (`mysql.connector.connection.MySQLConnection` object).
- Use the `os` module to obtain credentials from the environment.
- Use the module `mysql-connector-python` to connect to the MySQL database (`pip3 install mysql-connector-python`)

### 4. Read and filter data
Implement a `main` function that takes no arguments and returns nothing.

The function will obtain a database connection using `get_db` and retrieve all rows in the `users` table and display each row under a filtered format like this:
```
[HOLBERTON] user_data INFO 2019-11-19 18:37:59,596: name=***; email=***; phone=***; ssn=***; password=***; ip=e848:e856:4e0b:a056:54ad:1e98:8110:ce1b; last_login=2019-11-14T06:16:24; user_agent=Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; KTXN);
```
Filtered fields:
- name
- email
- phone
- ssn
- password

Only your `main` function should run when the module is executed.


### 5. Encrypting passwords
User passwords should NEVER be stored in plain text in a database.

Implement a `hash_password` function that expects one string argument name `password` and returns a salted, hashed password, which is a byte string.

Use the `bcrypt` package to perform the hashing (with `hashpw`).


### 6. Check valid password
Implement an `is_valid(hashed_password:bytes type, password: string type)` function that expects 2 arguments and returns a boolean.

**Requrement**
Use `bcrypt` to validate that the provided password matches the hashed password.
