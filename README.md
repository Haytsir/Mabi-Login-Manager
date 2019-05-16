# Mabi-Login-Manager
Mabinogi login manager implemented in python which can launch the game without through web page (KR server only)

## Usage
First of all, You might have to make a directory named 'cache'
where the module saves encrypted login informations and passport caches

You can just import the module, then create a instance of it.
It has cmd interface just for now,  Login method will prints it on the prompt.
```python
from LoginManager import LoginManager
login = LoginManager()
NPP, passport = login.Login()
```

## Requirements
Cryptodome
