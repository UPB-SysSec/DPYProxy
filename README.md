# DPYProxy
DPYProxy is a python proxy that implements DPI evasion mechanisms. Currently, TLS record fragmentation and TCP
Fragmentation are implemented. All DPI evasion mechanisms can be enabled separately.

You can run DPYProxy locally or on a separate machine. It functions like an HTTP CONNECT proxy. I.e., you can specify
it as your Firefox/Chrome/System Proxy. Socksv4/Socksv5 support is planned in the future.

In a typical setup, DPYProxy runs locally replacing your previous proxy in your browser or system setup. You can specify
your previous proxy as a forward proxy for DPYProxy. This can be helpful if you need DPYProxy for DPI evasion and a
separate proxy for IP censorship circumvention.

# Requirements
- python3
  - `sudo apt install python3`
- dnspython (if the dot setting is used)
  - `pip3 install -r requirements.txt`
- docker (if you want to run DPYProxy in a container)
  - https://docs.docker.com/engine/install/
  - 
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

Standard options:
  -h, --help            Show this help message and exit
  --debug, --no-debug   Turns on debugging (default: False)
  --disabled_modules DISABLED_MODULES
                        List of proxy modules to disable. By default, all none
                        are disabled. Hence, all are enabled
```

## Settings

### --debug
Turns on debugging statements.

### --proxy_mode
DPYProxy proxies based on the first message it receives. It can infer a destination from **HTTP GET** messages,
**HTTP CONNECT** messages and **TLS ClientHello** messages that contain the **SNI** extension. By default, DPYProxy 
detects the message type automatically. You can restrict it to a specific type using this argument. Use HTTP for 
HTTP GET messages, HTTPS for HTTP CONNECT messages and SNI for TLS ClientHello messages.

### --timeout
The timeout for which to keep open the connections in either direction. If no data is received for the specified time, 
DPYProxy cancels the socket. In seconds.

### --port
The port on which DPYProxy listens for incoming connections.

### --record_frag
Enables TLS record fragmentation. Any received TLS handshake message is fragmented into multiple TLS records. The size 
can be specified by --frag-size. When run in combination with --tcp-frag, a TLS record is contained in a slightly larger TCP segment
that accounts for header bytes.

### --tcp_frag
Enables TCP fragmentation. Any received TCP message is fragmented into multiple TCP segments. The size can be specified
by --frag-size. When run in combination with --record-frag, a TLS record is contained in a slightly larger TCP segment
that accounts for header bytes.

### --frag-size
The size of the fragments in bytes. The default is 20 bytes. Note that a large fragment size can lead to no 
fragmentation for smaller messages.

### --tls_dns_server_ip
The IP address of the DNS server to use by the TCP proxy. If not specified, the OS default DNS server is used. This is only relevant if you use the DNS over TLS circumve

### --tls_dns_server_port
DNS server port for all DNS queries. Only set if a DNS server IP is given. If not given, the default port 53 is used.

### --forward_proxy_...
You can specify a forward proxy for IP censorship circumvention. DPYProxy will forward any message it receives to the 
forward proxy instead of the destination. You can specify the address and port of the forward proxy as well as its mode
of operation. For example, you can specify a forward proxy that only proxies HTTP CONNECT messages. DPYProxy will send 
the corresponding message to the server. You can also specify whether DPYProxy should resolve the domain before sending
the HTTP CONNECT message to the forward proxy. This can be helpful if the forward proxy does not support DNS resolution.

## Examples

`python3 main.py --record_frag --no-tcp_frag` launches DPYProxy with TLS record fragmentation enabled. TCP fragmentation is 
turned off.

`python3 main.py --no-record_frag --no-tcp_frag --debug` launches DPYProxy without any censorship circumvention techniques but enables debugging.

`python3 main.py --frag_size 100` launches DPYProxy with both TLS record and TCP fragmentation
and sets the fragment size to 100 bytes. The TLS record will be of size 100 while the encompassing TCP segments will be
just large enough to contain the fragmented TLS record.

`python3 main.py --record_frag --dot --dot_resolver 8.8.8.8 --port 443` launches DPYProxy on port 443 and enables TLS record fragmentation. 
It also enables DNS over TLS to resolve the domain of the destination. For that, it uses Google's DNS server `8.8.8.8`.

`python3 main.py --record_frag --forward_proxy_address 192.168.0.1 --forward_proxy_port 8080 --forward_proxy_mode HTTPS 
--forward_proxy_resolve_address` launches DPYProxy with TLS record fragmentation and a forward proxy. The forward proxy 
is specified by its address and port. While DPYProxy accepts HTTP GET, HTTP CONNECT and TLS ClientHello messages for 
proxying, it connects to the forward proxy using HTTP CONNECT.

## Testing

Setup DPYProxy using 
```sh
python3 main.py --record_frag --tcp_frag --frag_size 20 --port 4433
```

you can test it using curl
```sh
curl -p -x localhost:4433 https://www.wikipedia.org
```

using some kind of capturing tool like wireshark you can inspect the fragmented TLS records and TCP segments.

# Docker

You can run DPYProxy in a Docker container. A standard setting is provided in the `docker-compose.yml` file. You can
also build the image yourself using the provided `Dockerfile` or change the parameters in the `docker-compose.yml` file.

Start the container with 
```sh
docker-compose up
```

# Roadmap

I developed DPYProxy when writing a blogpost in which I circumvented the GFW with TLS record fragmentation. Thus, the 
functionality of DPYProxy is currently limited. Below, I gathered some potential avenues for the future.

## Implemented
- [x] HTTP Connect Proxy
- [x] SNI Proxy
- [x] Socksv4/Sockv5 proxy
- [x] TLS record fragmentation
- [x] TCP Fragmentation
- [x] DNS

## Todo
- [ ] HTTP shenanigans
- [ ] unit tests...
- [ ] IPv6