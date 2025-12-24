# mshrt

meshrt is a <b>m</b>e<b>sh</b> <b>r</b>ou<b>t</b>er inspired by
[yggdrasil](https://yggdrasil-network.github.io]), but intended to be
extensible to use cases beyond an internet overlay network.

## Features

* Connect to other nodes via UDP
* Connect to other nodes via WebSocket
* Post quantum confidentiality (resistant to store-now-decrypt-later) via
  [ML-KEM](https://docs.rs/ml-kem/latest/ml_kem/)
* tun interface with mesh routable IPv6 address derived from node's public key

## Usage

```plain
mshrt 0.1.0
Sharp Hall <sharp@sharphall.org>

USAGE:
    mshrt [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --config <config>                        Sets a custom config file
    -C, --ws_connect <connect_addresses>         A comma separated list of addresses to connect to
    -l, --ws_listen <listen_addresses>           A comma separated list of bind addresses
    -p, --private_key <private_key>              base64 encoded private key
        --tun <tun>                              Run tun interface
    -U, --udp_connect <udp_connect_addresses>    A comma separated list of addresses to connect to
    -u, --udp_listen <udp_listen_address>        The UDP address to bind to
```

## Example

### Machine A (1.2.3.4)

```plain
mshrt -u 0.0.0.0:1111 --tun true
```

### Machine B (2.3.4.5)

```plain
mshrt -u 0.0.0.0:1111 -U 1.2.3.4:1111 --tun true
```

### Machine C (3.4.5.6)

```plain
mshrt -u 0.0.0.0 -U 2.3.4.5:1111 --tun true
```

Machine C should now be able to communicate to Machine A over the IPv6 address
it prints on startup. It will also display a private key so that the machine's
identity can be persisted across executions with `--private_key <private_key>`.

## Future plans

* Support really big networks through sharding and subset networks
* Better link monitoring and route choosing
* Connect to other nodes via meshtastic?
