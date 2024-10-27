#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#include "checksum.h"
#include "metrics.h"
#include "net.h"
#include "packet.h"
#include "receive.h"
#include "secret.h"
#include "sender.h"
#include "time.h"
#include "usergroup.h"

Secret secret;
Metrics metrics;
Sender sender;
Receiver receiver;

struct {
    std::string user;
    std::string group;
} cf;

void sender_thread_main() {
    sender.loop();
}

void metrics_thread_main() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        metrics.rotate();
    }
}

void addrs_thread_main() {
    for (;;) {
        for (auto &[_, path] : sender.paths4) {
            if (path.src_addr_dyn == true && path.dst_addr != 0) {
                uint32_t src_addr = get_source_addr(path.dst_addr);
                if (src_addr != path.src_addr) {
                    path.src_addr = src_addr;
                    std::cout << "Source for path " << path.src_name << " -> " << path.dst_name << " updated to " << inet_ntoa({src_addr}) << std::endl;
                }
            }
        }
        char ip6[INET6_ADDRSTRLEN], addr6[16];
        static const char ipv6_zeros[16] = {0};
        for (auto &[_, path] : sender.paths6) {
            if (path.src_addr_dyn == true && memcmp(path.dst_addr, ipv6_zeros, 16) != 0) {
                get_source_addr(addr6, path.dst_addr);
                if (memcmp(path.src_addr, addr6, 16) != 0) {
                    memcpy(path.src_addr, addr6, 16);
                    // Log that the source address has changed.
                    inet_ntop(AF_INET6, path.dst_addr, ip6, INET6_ADDRSTRLEN);
                    std::cout << "Source for path " << path.src_name << " -> " << path.dst_name << " updated to " << ip6 << std::endl;
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

/**
 * Read configuration from a file.
 */
void read_configuration(const char *file_name) {
    int i;

    std::ifstream file;
    file.open(file_name);
    if (!file.is_open()) {
        throw std::system_error(errno, std::system_category(), "Error opening configuration file");
    }

    std::string line;
    while (std::getline(file, line)) {
        std::cout << file_name << ": " << line << std::endl;

        std::istringstream iss(line);

        std::string cmd;
        iss >> cmd;

        if (cmd == "secret") {
            // Skip whitespace and then read the rest of the line.
            std::getline(iss >> std::ws, secret.secret, '\0');
        } else if (cmd == "queue_dir") {
            iss >> metrics.queue_dir;
        } else if (cmd == "queue_max_file_size") {
            iss >> metrics.max_queue_file_size;
        } else if (cmd == "queue_rotate_after_size") {
            iss >> metrics.rotate_after_size;
        } else if (cmd == "queue_max_file_count") {
            iss >> metrics.max_file_count;
        } else if (cmd == "user") {
            iss >> cf.user;
        } else if (cmd == "group") {
            iss >> cf.group;
        } else if (cmd == "dev") {
            iss >> receiver.dev;
        } else if (cmd == "src_port") {
            iss >> sender.src_port;
        } else if (cmd == "dst_port") {
            iss >> sender.dst_port;
        } else if (cmd == "ports_count") {
            iss >> sender.ports_count;
        } else if (cmd == "packet_size") {
            iss >> sender.packet_size;
        } else if (cmd == "interval") {
            iss >> sender.interval_ms;
        } else if (cmd == "path4") {
            std::string src_name;
            std::string src_ip;
            std::string dst_name;
            std::string dst_ip;

            iss >> src_name;
            iss >> src_ip;
            iss >> dst_name;
            iss >> dst_ip;

            auto src_addr = inet_addr(src_ip.c_str());
            auto dst_addr = inet_addr(dst_ip.c_str());

            bool src_addr_dyn = false;
            if (src_ip == "-" || src_ip == "dynamic") {
                src_addr = 0;
                src_addr_dyn = true;
            }

            bool dst_addr_dyn = false;
            if (dst_ip == "-" || dst_ip == "dynamic") {
                dst_addr = 0;
                dst_addr_dyn = true;
            }

            if (src_name.size() > MAX_NAME_SIZE) {
                throw std::runtime_error("Source name is too long: " + src_name);
            }
            if (dst_name.size() > MAX_NAME_SIZE) {
                throw std::runtime_error("Destination name is too long: " + dst_name);
            }

            if (src_addr == INADDR_NONE) {
                throw std::runtime_error("Invalid source IP: " + src_ip);
            }
            if (dst_addr == INADDR_NONE) {
                throw std::runtime_error("Invalid destination IP: " + dst_ip);
            }

            Path4 path;
            memset(&path, 0, sizeof(path));
            strcpy(path.src_name, src_name.c_str());
            strcpy(path.dst_name, dst_name.c_str());
            path.src_addr = src_addr;
            path.dst_addr = dst_addr;
            path.src_addr_dyn = src_addr_dyn;
            path.dst_addr_dyn = dst_addr_dyn;

            sender.add_path4(src_name.c_str(), dst_name.c_str(), path);
        } else if (cmd == "path6") {
            std::string src_name;
            std::string src_ip;
            std::string dst_name;
            std::string dst_ip;

            iss >> src_name;
            iss >> src_ip;
            iss >> dst_name;
            iss >> dst_ip;

            Path6 path;
            memset(&path, 0, sizeof(path));

            if (src_name.size() > MAX_NAME_SIZE) {
                throw std::runtime_error("Source name is too long: " + src_name);
            }
            strcpy(path.src_name, src_name.c_str());

            if (dst_name.size() > MAX_NAME_SIZE) {
                throw std::runtime_error("Destination name is too long: " + dst_name);
            }
            strcpy(path.dst_name, dst_name.c_str());

            if (src_ip == "-" || src_ip == "dynamic") {
                path.src_addr_dyn = true;
            } else {
                i = inet_pton(AF_INET6, src_ip.c_str(), &path.src_addr);
                if (i != 1) {
                    throw std::runtime_error("Invalid source IP: " + src_ip);
                }
                path.src_addr_dyn = false;
            }

            if (dst_ip == "-" || dst_ip == "dynamic") {
                path.dst_addr_dyn = true;
            } else {
                i = inet_pton(AF_INET6, dst_ip.c_str(), &path.dst_addr);
                if (i != 1) {
                    throw std::runtime_error("Invalid destination IP: " + dst_ip);
                }
                path.dst_addr_dyn = false;
            }

            sender.add_path6(src_name.c_str(), dst_name.c_str(), path);
        } else if (cmd != "" && cmd[0] != '#') {
            throw std::runtime_error("Unknown option: " + cmd);
        }
    }
    if (!file.eof()) {
        throw std::system_error(errno, std::system_category(), "Error reading configuration file");
    }

    if (sender.ports_count < 1 || sender.ports_count > 65536) {
        throw std::runtime_error("Invalid ports_count: " + std::to_string(sender.ports_count));
    } else if (sender.src_port < 0 || sender.src_port > 65535 - sender.ports_count + 1) {
        throw std::runtime_error("Invalid src_port: " + std::to_string(sender.src_port));
    } else if (sender.dst_port < 0 || sender.dst_port > 65535 - sender.ports_count + 1) {
        throw std::runtime_error("Invalid dst_port: " + std::to_string(sender.dst_port));
    } else if (sender.packet_size <= 40 + 20 + 56) {  // IP6+TCP+PacketFormat
        throw std::runtime_error("Invalid packet_size: " + std::to_string(sender.packet_size));
    } else if (sender.interval_ms < 10) {
        throw std::runtime_error("Invalid interval: " + std::to_string(sender.interval_ms));
    }

    if (metrics.max_file_count <= 0) {
        throw std::runtime_error("Invalid max_file_count: " + std::to_string(metrics.max_file_count));
    } else if (metrics.max_queue_file_size <= 0) {
        throw std::runtime_error("Invalid max_queue_file_size: " + std::to_string(metrics.max_queue_file_size));
    } else if (metrics.rotate_after_size <= 0 || metrics.rotate_after_size >= metrics.max_queue_file_size) {
        throw std::runtime_error("Invalid rotate_after_size: " + std::to_string(metrics.rotate_after_size));
    }
}

int main(int argc, char *argv[]) {
    // Default configuration.
    secret.secret = "secret";
    sender.src_port = 43000;
    sender.dst_port = 65000;
    sender.ports_count = 100;
    sender.packet_size = 1250;
    sender.interval_ms = 100;
    receiver.dev = "eth0";

    // Read configuration files.
    for (int i = 1; i < argc; i++) {
        read_configuration(argv[i]);
    }

    // Open socket and network device.
    sender.open();
    receiver.open();
    metrics.open();
    switch_user_and_group(cf.user, cf.group);

    // Start running.
    std::thread addrs_thread(addrs_thread_main);
    std::thread sender_thread(sender_thread_main);
    std::thread metrics_thread(metrics_thread_main);
    receiver.loop();

    return 1;
}
