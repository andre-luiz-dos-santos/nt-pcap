# Network Test

Send IP4/IP6 TCP/UDP/ICMP packets and count how many have reached the destination, the time it took to arrive and the TTL.

## Build instructions

### cmake

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Configuration

All command-line arguments are interpreted as configuration file names.
Configure the application using the following options.

- `secret`: Specify the same key on all hosts.
- `queue_dir`: Set the directory for the metrics queue.
- `user`: Define the user for the process.
- `group`: Define the group for the process.
- `dev`: Specify the device to listen for packets on.
- `src_port`: Set the first source port number.
- `dst_port`: Set the first destination port number.
- `ports_count`: Number of ports to use, starting from `src_port` and `dst_port`.
- `packet_size`: Packet size in bytes, including the IP header.
- `interval`: Set the interval between packets (milliseconds).
- `path4`: List of IPv4 addresses to send and receive packets.
- `path6`: List of IPv6 addresses to send and receive packets.

Options `path4` and `path6` follow a similar pattern: `local-name local-ip remote-name remote-ip`.  If the IP is dynamic, it can be replaced with `-`. At least one end must have a static address.

Files in `queue_dir` are compressed with `zstd`. The program will refuse to start if any unrecognizable file names are found in this directory.

Example configuration file:
```text
secret my_secret_key
queue_dir /path/to/queue
user myuser
group mygroup
dev eth0
src_port 12345
dst_port 54321
ports_count 10
packet_size 1000
interval 100
path4 myname 1.1.1.1 abc 2.2.2.2
path4 myname 3.3.3.3 def 4.4.4.4
path6 myname - def 2001:db8::1
```
