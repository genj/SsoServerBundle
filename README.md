# genjSsoServerBundle

The server side bundle to add Single Sign-On login functionality to your site

## Requirements

* Curl

## Installation

Add the bundle to your composer.json

```
"require": {
    ...
    "genj/sso-server-bundle": "dev-master"
}
```

Add the following pararmeters to your config.yml

```
genj_sso_server:
    brokers:
        SPECIALNAME:
            secret: SUPERSECRETTOKEN
```

Add the following routes to your routing.yml

```
genj_sso_server_command:
    pattern:  /sso/command/{brandIdentifier}
    defaults: { _controller: GenjSsoServerBundle:Sso:index }
```


