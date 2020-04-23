import os

from pypmp import PasswordManagerProClient

pmp = PasswordManagerProClient(os.environ.get("PMP_HOSTNAME"), os.environ.get("PMP_TOKEN"), verify=False)
