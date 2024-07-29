# Easy credentials

Simple set of classes to manage credentials (user/pwd, token...)

## Installation

Classic through pip or your favourite package manager:

```shell
pip install ez-credentials
```

## Usage

Instantiate a credential manager. The instance is callable and returns the credentials. You can also get the credentials as a dictionnary or as a tuple.

```python
from ez_credentials import CredentialManager

cred = CredentialManager('test')

cred()
```

You'll be prompted for your credentials. They will be stored in your keyring. 

'test' is the name of the service. You can define several credential managers with different service names.

Optionally, you cat set how long the credentials should be stored, i.e. how frequently the password is asked for.
This is defined in seconds, and default to 30 days.

```python
from time import sleep
from ez_credentials import CredentialManager

cred = CredentialManager('test', expires_in=1)

cred()
sleep(1)
cred()
```

There are other classes (TokenManager, TokenCredentialManager, WebServiceTokenManager and WebServiceTorkenManager; and some aliases).
