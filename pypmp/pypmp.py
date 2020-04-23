#!/usr/bin/env python3
# coding: utf-8

import json
import logging

import requests


LOGGER = logging.getLogger(__name__)


class PasswordManagerProClient(object):
    def __init__(self, hostname, token, port=443, verify=True):
        self.token = token
        self.verify = verify
        self._API_URL = f"https://{hostname}:{port}/restapi/json/v1"

    def _request(self, method, endpoint, params=None, jdata=None):
        if jdata:
            if not params:
                params = {}
            params["INPUT_DATA"] = json.dumps(jdata)
        res = requests.request(
            method=method,
            url=f"{self._API_URL}/{endpoint}",
            headers={"AUTHTOKEN": self.token, "Content-Type": "text/json"},
            params=params,
            verify=self.verify,
        )
        res.raise_for_status()
        jres = res.json()
        print(f'{jres["operation"]["result"]}')
        LOGGER.info(f'{jres["operation"]["result"]}')
        if jres["operation"]["result"]["status"] != "Success":
            LOGGER.warning(
                f'Request to {res.url} failed: {jres["operation"]["result"]["message"]}'
            )
        return jres["operation"].get("Details")

    def _get(self, endpoint, params=None, jdata=None):
        return self._request(
            method="get", endpoint=endpoint, params=params, jdata=jdata
        )

    def _post(self, endpoint, params=None, jdata=None):
        return self._request(
            method="post", endpoint=endpoint, params=params, jdata=jdata
        )

    def _put(self, endpoint, params=None, jdata=None):
        return self._request(
            method="put", endpoint=endpoint, params=params, jdata=jdata
        )

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

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getid
    def get_account_and_resource_ids(self, resource_name, account_name):
        return self._get(
            endpoint="resources/getResourceIdAccountId",
            params={"RESOURCENAME": resource_name, "ACCOUNTNAME": account_name},
        )

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getresid
    def get_resource_id(self, resource_name):
        res = self._get(endpoint=f"resources/resourcename/{resource_name}")
        return res.get("RESOURCEID")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#createuser
    def create_user(
        self,
        username,
        password,
        first_name="",
        last_name="",
        full_name="",
        role="Password User",
        email="",
        department="",
        hostname="",
        location="",
        password_policy="Strong",
        api_user=False,
        superadmin=False,
        expiration="NeverExpires",
    ):
        # bool -> str
        superadmin = str(superadmin).lower()
        api_user = str(api_user).lower()

        data = {
            "operation": {
                "Details": {
                    "USERNAME": username,
                    "FIRSTNAME": first_name,
                    "LASTNAME": last_name,
                    "FULLNAME": full_name,
                    "EMAIL": email,
                    "POLICY": password_policy,
                    "ROLE": role,
                    "ISSUPERADMIN": superadmin,
                    "PASSWORD": password,
                    "DEPARTMENT": department,
                    "LOCATION": location,
                    "ISAPIUSER": api_user,
                    "HOSTNAME": hostname,
                    "EXPIRYDATE": expiration,
                }
            }
        }
        from pprint import pprint
        pprint(data)
        return self._post("user", jdata=data)

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#getID
    def get_user_id(self, username):
        res = self._get(endpoint="user/getUserId", params={"USERNAME": username})
        return res.get("USERID")

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#unlockUser
    def unlock_user(self, username):
        return self._put(endpoint="user/unlock", params={"USERNAME": username})

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#lockUser
    def lock_user(self, username):
        return self._put(endpoint="user/lock", params={"USERNAME": username})

    # https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html#generatepswd
    def generate_password(self, password_policy="Strong"):
        data = {"operation": {"Details": {"POLICY": password_policy}}}
        # res = self._get("passwords/generate", params=data)
        res = self._get("passwords/generate", jdata=data)
        return res.get("PASSWORD")

    # Shortcuts
    def get_resource_by_name(self, name):
        for res in self.get_resources():
            if res.get("RESOURCE NAME") == name:
                return res

    def get_account_by_name(self, resource_name, account_name):
        resource = self.get_resource_by_name(resource_name)
        for acc in [
            x
            for x in self.get_accounts(resource.get("RESOURCE ID")).get("ACCOUNT LIST")
        ]:
            if acc.get("ACCOUNT NAME") == account_name:
                return acc

    def get_password(self, resource_name, account_name):
        resource = self.get_resource_by_name(resource_name)
        account = self.get_account_by_name(resource_name, account_name)
        return self.get_account_password(
            resource.get("RESOURCE ID"), account.get("ACCOUNT ID")
        )
