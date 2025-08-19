# DPYProxy-DNS
We extended DPYProxy with modularization and a new DNS module. The already existing code for TLS circumventions was moved to the TLS module.

You can run DPYProxy(-DNS) locally or on a separate machine. It is a DNS/TLS proxy, dependent on the running modules. Both can run at
the same time and in this case the TLS module uses the DNS proxy internally by default.

In the following, we detail the requirements, usage, and examples.

# Requirements
- python3
  - `sudo apt install python3`
- packages
  - `pip3 install -r requirements.txt`
- docker (if you want to run DPYProxy in a container)
  - https://docs.docker.com/engine/install/
  
# Usage

```
usage: main.py [options]

Proxy for circumventing DPI-based censorship.

TLS Module:
  --tls_disabled_modes {HTTP,HTTPS,SNI,SOCKSv4,SOCKSv4a,SOCKSv5}
                        List of proxy modes to ignore. By default, all none
                        are disabled. Hence, all are enabled
  --tls_timeout TLS_TIMEOUT
                        Connection timeout in seconds
  --tls_host TLS_HOST   Address the proxy server runs on
  --tls_port TLS_PORT   Port the proxy server runs on
  --tls_record_frag, --no-tls_record_frag
                        Whether to use record fragmentation to forwarded TLS
                        handshake messages (default: True)
  --tls_tcp_frag, --no-tls_tcp_frag
                        Whether to use TCP fragmentation to forwarded
                        messages. (default: True)
  --tls_frag_size TLS_FRAG_SIZE
                        Bytes in each TCP/TLS record fragment
  --tls_dns_server_ip TLS_DNS_SERVER_IP
                        DNS server IP for all DNS queries of the TLS module.
                        If not given, the DNS server started by the DNS module
                        us used. If DNS module is not used, the OS default DNS
                        server is used.
  --tls_dns_server_port TLS_DNS_SERVER_PORT
                        DNS server port for all DNS queries. Only set if a DNS
                        server IP is given. If not given, the default port 53
                        is used.
  --tls_forward_proxy_host TLS_FORWARD_PROXY_HOST
                        Host of the forward proxy if any is present
  --tls_forward_proxy_port TLS_FORWARD_PROXY_PORT
                        Port the forward proxy server runs on
  --tls_forward_proxy_mode {HTTP,HTTPS,SNI,SOCKSv4,SOCKSv4a,SOCKSv5}
                        The proxy type of the forward proxy
  --tls_forward_proxy_resolve_address, --no-tls_forward_proxy_resolve_address
                        Whether to resolve domains before including them in
                        the HTTP CONNECT request to the second proxy (default:
                        False)

DNS Module:
  --dns_mode DNS_MODE   Mode that the DNS proxy operates in. Default AUTO. If
                        not set to AUTO, still attempts to automatically
                        determine a resolver for the configured mode. To pre-
                        define the used DNS mode and server set this flag and
                        the dns_resolver_host and optionally the
                        dns_resolver_port flags.
  --dns_timeout DNS_TIMEOUT
                        Connection timeout in seconds. For the LAST_RESPONSE
                        mode this timeout will always be reached. Set this
                        timeout and the timeout of calling application
                        accordingly.
  --dns_host DNS_HOST   Address the proxy server runs on
  --dns_port DNS_PORT   Port the proxy server runs on
  --dns_resolver_host DNS_RESOLVER_HOST
                        DNS resolver IP. If set, must correspond to the
                        selected dns_mode.
  --dns_resolver_port DNS_RESOLVER_PORT
                        DNS resolver port. If set, must correspond to the
                        selected dns_mode. If unset, port is chosen based on
                        the chosen or determined mode's standard port
  --dns_censored_domain DNS_CENSORED_DOMAIN
                        A domain name censored in your location. Used to
                        determine working circumventions methods. Specify
                        together with --dns_censored_domain_ip
  --dns_compare_ip_ranges DNS_COMPARE_IP_RANGES
                        A list of IP ranges the resolved IP of the censored
                        domain lies in. The censored domain is specifiable in
                        --dns_censored_domain.
  --dns_block_page_ips DNS_BLOCK_PAGE_IPS
                        Whether the given IP ranges to compare are block page
                        IPs or not. Default is False.
  --dns_add_sni DNS_ADD_SNI
                        Whether or not to include the SNI for encrypted DNS
                        modes. Defaults to True.
  --dns_skip_working_file
                        Whether taking the stored working resolver from a file should be skipped.
                        Defaults to False.

Standard options:
  -h, --help            Show this help message and exit
  --debug, --no-debug   Turns on debugging (default: False)
  --disabled_modules DISABLED_MODULES
                        List of proxy modules to disable. By default, all none
                        are disabled. Hence, all are enabled
```

## Examples

`python3 main.py --disabled_modules TLS` launches DPYProxy with just the DNS module enabled. The TLS module is disabled and not
used at all. The DNS module starts in its auto mode by default.

`python3 main.py --tls_record_frag --no-tls_tcp_frag` launches DPYProxy with TLS record fragmentation enabled. TCP fragmentation is 
turned off. The DNS module is also enabled with its default auto mode to determine a working circumvention. Using this circumvention, a
resolver is started that can be used on the system in general and is used by the TLS module by default.

`python3 main.py --tls_frag_size 100` launches DPYProxy with both TLS record and TCP fragmentation
and sets the fragment size to 100 bytes. The TLS record will be of size 100 while the encompassing TCP segments will be
just large enough to contain the fragmented TLS record. The DNS module is also enabled with its default auto mode to determine a working circumvention. Using this circumvention, a
resolver is started that can be used on the system in general and is used by the TLS module by default.

`python3 main.py --record_frag --forward_proxy_address 192.168.0.1 --forward_proxy_port 8080 --forward_proxy_mode HTTPS 
--forward_proxy_resolve_address` launches DPYProxy with TLS record fragmentation and a forward proxy. The forward proxy 
is specified by its address and port. While DPYProxy accepts HTTP GET, HTTP CONNECT and TLS ClientHello messages for 
proxying, it connects to the forward proxy using HTTP CONNECT. The DNS module is also enabled with its default auto mode to determine a working circumvention. Using this circumvention, a
resolver is started that can be used on the system in general and is used by the TLS module by default.

## Testing

Setup DPYProxy using 
```sh
python3 main.py --tls_record_frag --tls_tcp_frag --tls_frag_size 20 --tls_port 4433 --dns_port 5533
```

You can test the TLS circumventions using curl
```sh
curl -p -x localhost:4433 https://www.wikipedia.org
```

Using some kind of capturing tool like Wireshark, you can inspect the fragmented TLS records and TCP segments.

You can test the DNS circumventions using dig
```sh
dig wikipedia @127.0.0.1 -p 5533
```

Using some kind of capturing tool like Wireshark, you can inpect the made DNS requests for the selected circumvention strategy.
# Docker

You can run DPYProxy in a Docker container. A standard setting is provided in the `docker-compose.yml` file. You can
also build the image yourself using the provided `Dockerfile` or change the parameters in the `docker-compose.yml` file.

Start the container with: 
```sh
docker-compose up
```