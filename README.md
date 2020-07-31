# netdrop

![CI](https://github.com/klingtnet/netdrop/workflows/CI/badge.svg)

With netdrop you can send files or stream data from one peer to another inside a local network.
Data is encrypted on transport and there is zero configuration necessary, just share the password with the receiver.

netdrop uses zeroconf to detect peers which saves you from entering IP addresses.

## Installation

Just run `make install` or call `go run .` to run the application.

## Usage

In the following there are examples for some typical use cases of the tool.

### Send a File

```sh
# on the server side
$ netdrop send /path/to/my.file
password: usable-barnacle
waiting for connection...
# on the receiver side
$ netdrop receive usable-barnacle > /destination/my.file
```

### Pipe Through the Network

One example is to share a folder by piping the tar output.

```sh
# on the server side
$ tar -c /path/to/dir | netdrop send
tar -c ~/Downloads/wallpapers | netdrop send
password: climbing-crow
# on the receiver side
$ netdrop receive climbing-crow | tar -xC /destination/dir
```