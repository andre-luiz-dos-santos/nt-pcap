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
Configure the program using the following options.

- `secret`: Specify the same key on all hosts.
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
- `queue_dir`: Set the directory for the metrics queue.
- `queue_max_file_size`: Maximum uncompressed metrics file size in bytes.
- `queue_rotate_after_size`: Flush metrics to file after size bytes.
- `queue_max_file_count`: Maximum number of metrics files in `queue_dir`.

Options `path4` and `path6` follow a similar pattern: `local-name local-ip remote-name remote-ip`.  If the IP is dynamic, it can be replaced with `-`. At least one end must have a static address.

Files in `queue_dir` are compressed with `zstd`. The program will refuse to start if any unrecognizable file names are found in `queue_dir`. A new metrics file is created when `queue_dir` is empty or `queue_rotate_after_size` bytes have been collected in memory. If `queue_dir` has more than `queue_max_file_count` files, metrics will be dropped.

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
# Always send from 1.1.1.1 to 2.2.2.2.
path4 myname 1.1.1.1 abc 2.2.2.2
# Wait for 3.3.3.3 to start sending.
path4 myname 3.3.3.3 def -
# Use route table to select local IP.
path6 myname - def 2001:db8::1
```
