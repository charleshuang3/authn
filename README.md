# Authn

This project provides authentication for reverse proxies, supporting:

- Third party Login (Google Login)
- Local accounts (allow sign up with invitation code)
- HTTP basic auth (used in front of my webdav)

It functions as an OIDC provider, including an additional "roles" field for authorization purposes.

It uses a database (sqlite or postgresql) to store users.

## Configuration

The application is configured via a YAML file. See `config.sample.yaml` for example.

## Usage

```sh
go run cmd/authm/main.go -c config.yaml
```
