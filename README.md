# proto6749
Prototype for various OAuth related technologies, such as mTLS, PAR, and RAR.

## Current Featureset

Raw implementations of:

* OAuth 2.0 with authorization code grant and client credentials grant
* mTLS 
* RAR
* PAR

## Setup

### Install Postgres Database Server

On mac:
```
brew update
brew install postgresql
```

On ubuntu:
```
sudo apt install postgresql
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

The development server will be available at http://127.0.0.1:8000/, the admin interface at http://127.0.0.1:8000/admin

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

The server should now be available at https://localhost

### Run Tests (Requires nginx)
Note: The test files contain a statically configured client id and
secret. Until that is fixed, you need to create clients in the
database manually and change the settings in the test files.

```
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
cd tests
./client_credentials.py # etc.
```
