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

## Example Setup
Launching both

```python3 main.py --setting 0```

and

```python3 main.py --setting 1```

launches two instances of DPYProxy on your machine accessible under `127.0.0.1:4433`. The first instance injects TCP and
TLS record fragmentation into the connection. The second functions as a plain HTTP CONNECT proxy. This setup simulates
a usual deployment of DPYProxy.

## DPI setup
Without parameters, DPYProxy is accessible under ```127.0.0.1:4433``` and utilizes both TPC and TLS record
fragmentation for DPI circumvention.

```python3 main.py```

You can specify another proxy for IP censorship circumvention using the `--forward_proxy_<arg>` arguments.

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