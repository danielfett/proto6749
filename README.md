# proto6749
Prototype for various OAuth related technologies, such as mTLS, PAR, and RAR. Do not use this in production environments!

## Current Featureset

Raw implementations of:

* OAuth 2.0 with authorization code grant and client credentials grant
* mTLS for client authentication and token binding
* RAR
* PAR
* OAuth Server Metadata

## Setup

### Install Postgres Database Server

Make sure to install the postgres server and, at least on linux, the development libraries.

On mac:
```
brew update
brew install postgresql
```

On ubuntu:
```
sudo apt install postgresql postgresql-server-dev-all
```

### Setup Postgres User

Create a postgres database `django_oauth` and ensure that your user
either has access to the database without credentials (authentication
via system login) or set up username and password. No change in the
app's settings should be needed for the first option. If you use the
second option, create a file
`app/proto6749/settings.d/90-postgres_settings.py` and create the
django database configuration in this file, for example

```
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'django_oauth',
        'PASSWORD': 'password',
    }
}
```

Please refer to https://docs.djangoproject.com/en/2.2/ref/settings/#databases for configuration options.

### Install Dependencies

From the root directory of this repository:

```
virtualenv -p python3 env
source env/bin/activate
pip3 install -r app/requirements.txt
```

### Setup App

```
./app/manage.py migrate
./app/manage.py createsuperuser  # follow prompts
```

### Start App Without TLS
```
./app/manage.py runserver
```

The development server will be available at http://127.0.0.1:8000/, although with this path, it will only produce an error message. The admin interface at http://127.0.0.1:8000/admin/ (note the trailing slash).

After creating servers in the web interface, the servers' endpoints will be available at URLs starting with http://127.0.0.1:8000/servername/, where `servername` is the name of the respective server. To see all URLs for `servername` and further configuration information (see RFC8414), go to http://localhost:8000/.well-known/oauth-authorization-server/servername.

### Use nginx as TLS Reverse Proxy
Use the tool `mkcert` (https://github.com/FiloSottile/mkcert) to create certificates in the `nginx` subfolder:

```
cd nginx
wget 'https://github.com/FiloSottile/mkcert/releases/download/v1.4.1/mkcert-v1.4.1-linux-amd64' -Omkcert
chmod +x mkcert
./mkcert -install
./mkcert localhost
sudo nginx -c `pwd`/nginx.conf
```

The app server must be running via the `runserver` command. The server should now be available with TLS at https://localhost. Except for protocol and hostname/port, the URLs stay the same, e.g., https://localhost/.well-known/openid-configuration/servername.

### Run Tests (Requires nginx)
Note: The test files contain a statically configured client id and
secret. Until that is fixed, you need to create clients in the
database manually and change the settings in the test files.

```
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
cd tests
./client_credentials.py # etc.
```
