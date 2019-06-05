# Superset-JWT-Login Module

Simple implementation for login using JWT on Superset


## Install

- Clone this repo and copy file `customSecurity.py` to your **superset** venv folder `/venv/lib/python3.6/site-packages/superset/`
- Replace file `config.py` inside the **superset** folder or add the below code:

    ```python

    from .customSecurity import CustomSecurityManager
    CUSTOM_SECURITY_MANAGER = CustomSecurityManager

    # Custom JWT configuration
    JWT_POSTGRESBASE = 'postgresql+psycopg2://{0}:{1}@{2}:{3}/{4}'
    # See https://docs.sqlalchemy.org/en/13/core/engines.html
    JWT_CONNECTION_STRING = 'postgresql+psycopg2://{0}:{1}@{2}:{3}/{4}'
    JWT_HOST = '127.0.0.1'
    JWT_PORT = '5432'
    JWT_DB = 'myDB'
    JWT_DB_USER = 'myuser'
    JWT_DB_PASS = 'mydb'
    JWT_TABLE = 'sso_sset'

    ```
- In the chosen database execute the create statement, locate in file `jwt_ddl_model.sql`

- Restart superset and access our endpoint to login `/login/sso?token=<my-token>&redirect=<str-64-encoded>`

---
##### ATTENTION
> Only tested for versions 0.28.1 and 0.25.6
