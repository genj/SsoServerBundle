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

Add the bundle to your AppKernel.php

```
public function registerBundles() {
        $bundles = array(
            ...
            new Genj\SsoServerBundle\GenjSsoServerBundle(),
        );
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
genj_sso_server_command_attach:
    pattern:  /sso/command/attach
    defaults: { _controller: GenjSsoServerBundle:Sso:attach }

genj_sso_server_command_info:
    pattern:  /sso/command/info
    defaults: { _controller: GenjSsoServerBundle:Sso:info }

genj_sso_server_command_login:
    pattern:  /sso/command/login
    defaults: { _controller: GenjSsoServerBundle:Sso:login }

genj_sso_server_command_logout:
    pattern:  /sso/command/logout
    defaults: { _controller: GenjSsoServerBundle:Sso:logout }
```


