# PDNS

A personal dynamic DNS server.

Provides a simple HTTP API to update forward/reverse DNS records.

Works by updating zone files directly and then reloading something like nsd on changes.

get /?secret=<secret>&name=<name>&ip=<ip>

will update dns such that `name.origin = ip`