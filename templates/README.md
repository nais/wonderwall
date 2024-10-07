# Error templates

This directory contains `.gohtml` templates for static error pages served by Wonderwall.

These pages are typically only shown on exceptional errors, i.e. invalid configuration or infrastructure errors.
End-users should generally not see these pages unless something is really wrong.

We embed the CSS directly into the `.gohtml` templates.
This avoids implementing an endpoint to serve the CSS file separately.

## Prerequisites

If you haven't already, [install the Tailwind CSS CLI](https://tailwindcss.com/docs/installation).

## Development

```shell
make local
```

## Production

```shell
make build
```
