#!/usr/bin/env python3
# coding: utf-8

import logging

import requests


LOGGER = logging.getLogger(__name__)


class PasswordManagerProClient(object):
    def __init__(self, hostname, token, port=443, verify=True):
        self.token = token
        self.verify = verify
        self._API_URL = f"https://{hostname}:{port}/restapi/json/v1"

    def _get(self, endpoint):
        res = requests.get(
            url=f"{self._API_URL}/{endpoint}",
            headers={"AUTHTOKEN": self.token},
            verify=self.verify)
        res.raise_for_status()
        jres = res.json()
        if jres["operation"]["result"]["status"] != "Success":
            LOGGER.warning(f"Request to {res.url} failed.")
        return jres["operation"].get("Details")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getresource
    def get_resources(self):
        return self._get("resources")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getaccounts
    def get_accounts(self, resource_id):
        return self._get(f"resources/{resource_id}/accounts")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getaccountdetails
    def get_account(self, resource_id, account_id):
        return self._get(f"resources/{resource_id}/accounts/{account_id}")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getpwd
    def get_account_password(self, resource_id, account_id):
        data = self._get(f"resources/{resource_id}/accounts/{account_id}/password")
        return data.get("PASSWORD")

    # Shortcuts
    def get_resource_by_name(self, name):
        for res in self.get_resources():
            if res.get("RESOURCE NAME") == name:
                return res

    def get_account_by_name(self, resource_name, account_name):
        resource = self.get_resource_by_name(resource_name)
        for acc in [x for x in self.get_accounts(resource.get("RESOURCE ID")).get("ACCOUNT LIST")]:
            if acc.get("ACCOUNT NAME") == account_name:
                return acc

    def get_password(self, resource_name, account_name):
        resource = self.get_resource_by_name(resource_name)
        account = self.get_account_by_name(resource_name, account_name)
        return self.get_account_password(
            resource.get("RESOURCE ID"),
            account.get("ACCOUNT ID"))
