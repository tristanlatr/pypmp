# pypmp

Python lib to interact with ManageEngine Password Manager Pro's REST API

## Installation

```bash
pip install pypmp
```

## Usage

```python
from pypmp import PasswordManagerProClient

# Connect
pmp = PasswordManagerProClient("pmp.example.com", "REST_API_TOKEN", verify=True)

# Get all resources
pmp.get_resources()
# Get accounts
pmp.get_accounts(resource_id=resource_id)
# Get password
pmp.get_account_password(resource_id=resource_id, account_id=account_id)

# Shortcuts
# Get resource by name
pmp.get_resource_by_name(name="resource01")
# Get account by name
pmp.get_account_by_name(resource_name="resource01", account_name="Administrator")
# Get password
pmp.get_password(resource_name="resource01", account_name="Administrator")
```

## ``PasswordManagerProClient`` API Documentation

https://post-luxembourg.github.io/pypmp/pypmp.PasswordManagerProClient.html

## Password Manager Pro's REST API Documentation

https://www.manageengine.com/products/passwordmanagerpro/help/restapi.html
