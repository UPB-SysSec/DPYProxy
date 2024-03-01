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
# Usage

```
python3 main.py -h
      
usage: main.py [-h] [--setting SETTING] [--debug | --no-debug] [--proxy_mode {ALL,HTTP,HTTPS,SNI}] [--timeout TIMEOUT] [--port PORT] [--record_frag | --no-record_frag] [--tcp_frag | --no-tcp_frag] [--frag_size FRAG_SIZE] [--dot | --no-dot] [--dot_resolver DOT_RESOLVER]
               [--forward_proxy_address FORWARD_PROXY_ADDRESS] [--forward_proxy_port FORWARD_PROXY_PORT] [--forward_proxy_mode {ALL,HTTP,HTTPS,SNI}] [--forward_proxy_resolve_address | --no-forward_proxy_resolve_address]

Optional app description

options:
  -h, --help            show this help message and exit
  --setting SETTING     Fast setting for proxy setup.
  --debug, --no-debug   Turns on debugging (default: False)
  --proxy_mode {ALL,HTTP,HTTPS,SNI}
                        Which type of proxy to run
  --timeout TIMEOUT     Connection timeout in seconds
  --port PORT           Port the proxy server runs on
  --record_frag, --no-record_frag
                        Whether to use record fragmentation to forwarded tls handshake messages (default: False)
  --tcp_frag, --no-tcp_frag
                        Whether to use tcp fragmentation to forwarded messages. (default: False)
  --frag_size FRAG_SIZE
                        Bytes in each tpc/ tls record fragment
  --dot, --no-dot       Whether to use dot for address resolution (default: False)
  --dot_resolver DOT_RESOLVER
                        DNS server ip for DNS over TLS
  --forward_proxy_address FORWARD_PROXY_ADDRESS
                        Address of the forward proxy if any is present
  --forward_proxy_port FORWARD_PROXY_PORT
                        Port the forward proxy server runs on
  --forward_proxy_mode {ALL,HTTP,HTTPS,SNI}
                        The proxy type of the forward proxy
  --forward_proxy_resolve_address, --no-forward_proxy_resolve_address
                        Whether to resolve domain before including it in eventual HTTP CONNECT request to second proxy (default: False)
```

## Settings

### -- debug
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

### --dot
DPYProxy resolves any domain it receives to detect the IP address of the destination. By default, it uses the system DNS
server. By enabling this option, DPYProxy uses DNS over TLS to resolve the domain. You can specify the DNS server using
the --dot-resolver argument.

### --dot-resolver
The IP address of the DNS server to use for DNS over TLS. The default is Cloudflare's primary DNS server `1.1.1.1`.

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
- [x] TLS record fragmentation
- [x] TCP Fragmentation

## Todo
- [ ] SOCKSv4/5 Proxy
- [ ] HTTP shenanigans
- [ ] unit tests...
- [ ] sophisticated forwarding mechanism