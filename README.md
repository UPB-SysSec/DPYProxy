# DPYProxy
DPYProxy is a python proxy that implements DPI evasion mechanisms. To circumvent TLS censorship, TLS record fragmentation and TCP
segmentation are implemented. To circumvent DNS censorship, DPYProxy uses encrypted DNS and TCP segmentation. All DPI evasion mechanisms can be enabled separately.

DPYProxy comes with a TLS and DNS module circumventing TLS and DNS censorship respectively. Both modules are enabled by default.
DPYPRoxy also comes with an experimental HTTP module that is disables by default.


### DNS Module
You can run the DNS module of DPYProxy locally or on a separate machine. It functions as a DNS resolver that circumvents
DNS censorship. In a typical setup, DPYProxy runs locally replacing your previous DNS resolver in your system setup.

The DNS module automatically determines a working circumvention method and DNS resolver. You can also specify a 
circumvention method and resolver manually (see Usage). 

The DNS module can save working circumvention methods and resolvers to a file see 
(`--dns_working_resolver_configuration`). This file is loaded on startup to speed up the determination of a working
circumvention method. By default, a new working circumvention method is determined in each run.

### TLS Module
You can run the TLS Module of DPYProxy locally or on a separate machine. It functions like an HTTP CONNECT/SOCKSv4/SOCKSv5 proxy. I.e., you can specify
it as your Firefox/Chrome/System Proxy.

In a typical setup, DPYProxy runs locally replacing your previous proxy in your browser or system setup. You can specify
your previous proxy as a forward proxy for DPYProxy. This can be helpful if you need DPYProxy for DPI evasion and a
separate proxy for IP censorship circumvention.

The TLS module does not automatically determine a working circumvention method. You need to specify the circumvention 
method manually (see Usage). However, by default, the TLS module uses the DNS module to resolve DNS queries. 
Thus, if you run both modules, the DNS module automatically determines a working circumvention method for DNS queries 
used by the TLS module.

### HTTP Module
You can run the HTTP module of DPYProxy locally or on a separate machine. It functions like an HTTP CONNECT/SOCKSv4/SOCKSv5 proxy. I.e., you can specify
it as your Firefox/Chrome/System Proxy.

In a typical setup, DPYProxy runs locally replacing your previous proxy in your browser or system setup. You can specify
your previous proxy as a forward proxy for DPYProxy. This can be helpful if you need DPYProxy for DPI evasion and a
separate proxy for IP censorship circumvention.

The HTTP module does not automatically determine a working circumvention method. You need to specify the circumvention 
method manually (see Usage). Simple HTTP request alterations (e.g., lowercase request) and HTTP Request Smuggling 
strategies are implemented. A list of all implemented strategies can be found in: modules/http/HttpStrategies. 
**Be careful: HTTP request smuggling is a network attack against benign hosts and its implementation is experimental.
Plain HTTP traffic is also visible to any party that can read your traffic (such as your ISP). Use HTTPS (HTTP over TLS)
instead**

> The HTTP module is disabled by default. Enable by providing --disabled-modules ""

> HTTP request smuggling can be dangerous: https://portswigger.net/web-security/request-smuggling. Only enable if you
> know what you are doing and only use it against servers you have permission access via request smuggling. 
> HttpStrategies 100-129 are HTTP request smuggling strategies.

# Requirements
You can run DPYProxy with Python or Docker. The requirements for both options are listed below.
- python3 (if you want to run DPYPRoxy with Python)
  - `sudo apt install python3`
  - `pip3 install .` to run as module with `python3 main.py` or `python3 -m dpyproxy`
  - OR [install hatch](https://hatch.pypa.io/latest/install/) and run using `hatch run dpyproxy`
- docker (if you want to run DPYProxy in a container)
  - https://docs.docker.com/engine/install/
  
# Quick Start
Start DPYProxy with Docker: 
```sh
docker-compose up
```
Alternatively, start DPYProxy with Python:
```sh
python3 main.py --tls_record_frag --tls_tcp_frag --tls_frag_size 20 --tls_port 4433 --dns_port 5533
```
After automatically determining a circumvention method, the expected output looks like this:
```
INFO:root:DNS Module and TLS module found. Setting DNS server for TLS Module
INFO:root:Determining working circumvention method / resolver!
### Started TCP proxy on localhost:4433 ###
INFO:root:Found working circumvention method / resolver UDP - 1.0.0.3:53! Checking if consistently reachable!
INFO:root:UDP - 1.0.0.3:53 consistently reachable, keeping!
INFO:root:Finding consistent mode and starting resolvers took 0.0792999267578125 seconds in total.
### Started UDP DNS server on 127.0.0.1:5533 ###
### Started TCP DNS server on 127.0.0.1:5533 ###
```

DPYProxy now resolves all DNS requests to port 5533. 
You can send a DNS request to the DNS server using `dig`:
```sh
dig wikipedia.org @127.0.0.1 -p 5533
```

You can also configure the DNS resolver `127.0.0.1:5533` in any application that supports custom DNS resolvers, e.g., in your browser or system settings.

You can test the TLS circumventions using curl
```sh
curl -p -x localhost:4433 https://www.wikipedia.org
```

Detailed usage of DPYPRoxy-DNS and the original TLS module can be found below.

# Usage

```
usage: main.py [options]

Proxy for circumventing DPI-based censorship.

TLS Module:
  --tls_disabled_modes {HTTP,HTTPS,SNI,SOCKSv4,SOCKSv4a,SOCKSv5}
                        List of proxy modes to ignore. By default, all none
                        are disabled. Hence, all are enabled
  --tls_timeout TLS_TIMEOUT
                        Connection timeout in seconds (default: 10)
  --tls_host TLS_HOST   Address the proxy server runs on (default: localhost)
  --tls_port TLS_PORT   Port the proxy server runs on (default: 4433)
  --tls_record_version TLS_RECORD_VERSION
                        Overwrites the TLS version in the TLS record with the
                        given bytes. Pre-defined values ['DEFAULT', 'TLS10',
                        'TLS11', 'TLS12', 'TLS13_DRAFT_28', 'TLS13', 'SSL3',
                        'INVALID_SMALLER', 'INVALID_BIGGER'] or 2 byte long
                        values such as 0303 or FFFF can be provided. (default:
                        DEFAULT)
  --tls_record_frag, --no-tls_record_frag
                        Whether to use record fragmentation to forwarded TLS
                        handshake messages (default: True)
  --tls_tcp_frag, --no-tls_tcp_frag
                        Whether to use TCP fragmentation to forwarded
                        messages. (default: True)
  --tls_frag_size TLS_FRAG_SIZE
                        Bytes in each TCP/TLS record fragment (default: 20)
  --tls_dns_server_ip TLS_DNS_SERVER_IP
                        DNS server IP for all DNS queries of the TLS module.
                        If not given, the DNS server started by the DNS module
                        is used. If DNS module is not used, the OS default DNS
                        server is used.
  --tls_dns_server_port TLS_DNS_SERVER_PORT
                        DNS server port for all DNS queries. Only set if a DNS
                        server IP is given.
  --tls_forward_proxy_host TLS_FORWARD_PROXY_HOST
                        Host of the forward proxy if any is present. Example:
                        'localhost'
  --tls_forward_proxy_port TLS_FORWARD_PROXY_PORT
                        Port the forward proxy server runs on
  --tls_forward_proxy_mode {HTTP,HTTPS,SNI,SOCKSv4,SOCKSv4a,SOCKSv5}
                        The proxy type of the forward proxy (default: HTTPS)
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
                        dns_resolver_port flags. (default: AUTO)
  --dns_timeout DNS_TIMEOUT
                        Connection timeout in seconds. For the LAST_RESPONSE
                        mode this timeout will always be reached. Set this
                        timeout and the timeout of calling application
                        accordingly. (default: 3)
  --dns_host DNS_HOST   Address the proxy server runs on (default: 127.0.0.1)
  --dns_port DNS_PORT   Port the proxy server runs on (default: 5533)
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
                        together with --dns_compare_ip_ranges (default:
                        www.google.dj)
  --dns_compare_ip_ranges DNS_COMPARE_IP_RANGES
                        A list of IP ranges the resolved IP of the censored
                        domain lies in. The censored domain is specifiable in
                        --dns_censored_domain.
  --dns_block_page_ips DNS_BLOCK_PAGE_IPS
                        Whether the given IP ranges to compare are block page
                        IPs or not. (default: False)
  --dns_add_sni DNS_ADD_SNI
                        Whether or not to include the SNI for encrypted DNS
                        modes. (default: True)
  --dns_working_resolver_config DNS_WORKING_RESOLVER_CONFIG
                        DPYProxy can save a working DNS resolver
                        configuration, provide a location for this file here.
                        Example: ./.working_resolver_config.json. If empty
                        (default) no configuration is saved and a working
                        configuration is determined in each run.

HTTP Module:
  --http_timeout HTTP_TIMEOUT
                        Connection timeout in seconds (default: 10)
  --http_host HTTP_HOST
                        Address the proxy server runs on (default: localhost)
  --http_port HTTP_PORT
                        Port the proxy server runs on (default: 8080)
  --http_strategy HTTP_STRATEGY
                        Number of which specific http manipulation strategy to
                        apply. None: no manipulation, [1..70]: basic
                        manipulations, [101, 129]: Smuggling.See
                        HttpStrategies for meaning.
  --http_smuggling_uncensored_url HTTP_SMUGGLING_UNCENSORED_URL
                        Uncensored url to use for http smuggling. (default:
                        https://www.gov.cn/)

Standard options:
  -h, --help            Show this help message and exit
  --debug               Turns on debugging (default: False)
  --disabled_modules DISABLED_MODULES
                        List of proxy modules to disable. By default, only the
                        HTTP module is disabled. Available choices:
                        TLS,DNS,HTTP (default: HTTP)
  -v, --version         Show program's version
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

`python3 main.py --http_smuggling 23 --http_smuggling_uncensored_url 2` launches DPYProxy with HTTP Request Smuggling strategy number 23 enabled, using the second of three incorporated urls that are found to be uncensored (in china).  This specific strategy includes the Content-Length Header to set the bounds before the hidden request and the Transfer-Encoding Header to set them after the body to hide the second request. Additionally the Transfer-Encoding Header gets modified to include a 
second Colon (Transfer-Encoding:: chunked). 
A list of all implemented smuggling strategies (and direct manipulations) can be found in: modules/http/HttpStrategies. There you will also find the three uncensored urls.


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
dig wikipedia.org @127.0.0.1 -p 5533
```

Using some kind of capturing tool like Wireshark, you can inspect the made DNS requests for the selected circumvention strategy.
# Run in Docker

You can run DPYProxy in a Docker container. A standard setting is provided in the `docker-compose.yml` file. You can
also build the image yourself using the provided `Dockerfile` or change the parameters in the `docker-compose.yml` file.

Start the container with: 
```sh
docker-compose up
```

# Android

DPYProxy can also run on Android as a Kivy app with a foreground service. The TLS module listens on port 4433
and the DNS module on port 5533, both bound to `localhost`. Configure the app as your system's WLAN proxy
(`127.0.0.1:4433`) to route HTTP(S) traffic through it. The HTTP module is disabled by default on Android.

## Requirements

- python3 and a virtual environment (`python3 -m venv .venv && source .venv/bin/activate`)
- [buildozer](https://buildozer.readthedocs.io/en/latest/installation.html) (`pip install buildozer`)
- Java (`javac`), Git, and Cython — buildozer will download and manage the Android SDK/NDK itself on first build
- An Android device (or emulator) with USB or wireless debugging enabled, and `adb` on your machine

## Building

The build configuration lives in `buildozer.spec`. To build the debug APK without deploying it to a device:

```sh
buildozer android debug
```

The first build downloads the Android SDK/NDK and compiles all recipes, which can take a while. Subsequent
builds only rebuild what changed and are much faster. The resulting APK is placed in `bin/`.

## Running on a device

Connect a device via USB, or pair over Wi-Fi (Android 11+): on the device, enable Developer Options → Wireless
debugging → "Pair device with pairing code", then:

```sh
adb pair <ip>:<pairing-port> <pairing-code>
adb connect <ip>:<connect-port>
```

Build, install, launch, and stream the device log in one step:

```sh
buildozer android debug deploy run logcat
```

## Configuration

Unlike the CLI entry point (`main.py` on desktop), the Android service (`services/service.py`) does not accept
command-line arguments — it starts with a fixed set of defaults (`build_default_args()`). The app's Settings
tab lets you override the most relevant TLS/DNS options (ports, timeouts, fragmentation, DNS mode) while the
proxy is stopped; changes are saved to `dpyproxy_config.json` in the app's private storage and applied on the
next Start.

## Debugging

Service logs (visible in the app's Log tab) are also persisted to a JSON file in the app's private storage,
which can be pulled from a debug build via:

```sh
adb shell run-as de.upb.syssec.dpyproxy cat /data/user/0/de.upb.syssec.dpyproxy/files/dpyproxy_status.json
```

# Academic References

DPYProxy was developed as part of the following academic publication:

- `Poster: Circumventing the GFW with TLS Record Fragmentation` at ACM CCS 2023: https://dl.acm.org/doi/10.1145/3576915.3624372

Please reference it should you use DPYProxy in your research.

DPYProxy has previously been used in the following academic publications.

- `Transport Layer Obscurity: Circumventing SNI Censorship on the TLS-Layer` at IEEE S&P 2025: https://ieeexplore.ieee.org/abstract/document/11023326

- `A Wall Behind A Wall: Emerging Regional Censorship in China` at IEEE S&P 2025: https://ieeexplore.ieee.org/document/11023292

- `Towards Automated DNS Censorship Circumvention` at Virtual FOCI 2026: https://www.petsymposium.org/foci/2026/foci-2026-0001.php

# Roadmap

## Implemented
- [x] HTTP Connect Proxy
- [x] SNI Proxy
- [x] DNS Resolver
- [x] Socksv4/Sockv5 proxy
- [x] TLS record fragmentation
- [x] TCP Fragmentation
- [x] HTTP Circumventions

## Todo
- [ ] IPv6
- [ ] TLS Automation (as for DNS)

# Maintainance
- Run `ruff check --fix` to fix the auto fixable lint issues.
- Run `ruff format .` to pretty the code. Few could need a manual effort.