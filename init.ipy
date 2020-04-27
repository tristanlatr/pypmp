import os
import logging

logging.basicConfig(level=logging.DEBUG)

from pypmp import PasswordManagerProClient

pmp = PasswordManagerProClient(
    os.environ.get("PMP_HOSTNAME"),
    os.environ.get("PMP_TOKEN"),
    verify=False,
    debug=True
)
