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
    pthread_setname_np(pthread_self(), "nt:sender");
    sender.loop();
}

void receiver_thread_main() {
    pthread_setname_np(pthread_self(), "nt:receiver");
    receiver.loop();
}

void metrics_thread_main() {
    pthread_setname_np(pthread_self(), "nt:metrics");

    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        metrics.rotate();
    }
}

void addrs_thread_main() {
    uint32_t ip4;
    uint8_t ip6[16];

    pthread_setname_np(pthread_self(), "nt:addrs");

    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::lock_guard<std::mutex> guard(sender.mtx);

        for (auto &path : sender.paths4_vec) {
            if (path.src_ip_dyn == true && path.dst_ip4 != 0) {
                ip4 = get_source_ip_to(path.dst_ip4);
                if (path.src_ip4 != ip4) {
                    path.src_ip4 = ip4;
                    std::cout << "Source for path " << path.src_name << " -> " << path.dst_name
                              << " updated to " << ip_to_str(ip4) << std::endl;
                }
            }
        }

        for (auto &path : sender.paths6_vec) {
            if (path.src_ip_dyn == true && memcmp(path.dst_ip6, ipv6_zeros, 16) != 0) {
                get_source_ip_to(ip6, path.dst_ip6);
                if (memcmp(path.src_ip6, ip6, 16) != 0) {
                    memcpy(path.src_ip6, ip6, 16);
                    std::cout << "Source for path " << path.src_name << " -> " << path.dst_name
                              << " updated to " << ip_to_str(ip6) << std::endl;
                }
            }
        }
    }
}

void stats_main() {
    pthread_setname_np(pthread_self(), "nt:stats");

    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(60));
        std::lock_guard<std::mutex> guard(sender.mtx);

        std::cout << "--- Paths ---" << std::endl;

        for (const auto &path : sender.paths4_vec) {
            std::cout << path.src_name << " " << ip_to_str(path.src_ip4);
            if (path.src_ip_dyn) std::cout << " (dyn)";
            std::cout << " -> ";
            std::cout << path.dst_name << " " << ip_to_str(path.dst_ip4);
            if (path.dst_ip_dyn) std::cout << " (dyn)";
            if (path.index_timestamp_ms) std::cout << " ts=" << path.index_timestamp_ms;
            std::cout << std::endl;
        }

        if (sender.dyn_dst_paths4.empty() == false) {
            std::cout << "#";
            for (const auto &[dst_key, paths] : sender.dyn_dst_paths4) {
                std::cout << " " << dst_key.data() << ":";
                for (const auto path : paths) {
                    std::cout << "[" << path->src_name << "->" << path->dst_name << "]";
                }
            }
            std::cout << std::endl;
        }

        for (const auto &path : sender.paths6_vec) {
            std::cout << path.src_name << " " << ip_to_str(path.src_ip6);
            if (path.src_ip_dyn) std::cout << " (dyn)";
            std::cout << " -> ";
            std::cout << path.dst_name << " " << ip_to_str(path.dst_ip6);
            if (path.dst_ip_dyn) std::cout << " (dyn)";
            if (path.index_timestamp_ms) std::cout << " ts=" << path.index_timestamp_ms;
            std::cout << std::endl;
        }

        if (sender.dyn_dst_paths6.empty() == false) {
            std::cout << "#";
            for (const auto &[dst_key, paths] : sender.dyn_dst_paths6) {
                std::cout << " " << dst_key.data() << ":";
                for (const auto path : paths) {
                    std::cout << "[" << path->src_name << "->" << path->dst_name << "]";
                }
            }
            std::cout << std::endl;
        }
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
        throw std::system_error(errno, std::system_category(), "Failed to open");
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
            iss >> i;
            sender.interval = std::chrono::milliseconds(i);
        } else if (cmd == "path4") {
            std::string src_name;
            std::string src_addr;
            std::string dst_name;
            std::string dst_addr;

            iss >> src_name;
            iss >> src_addr;
            iss >> dst_name;
            iss >> dst_addr;

            if (src_name.size() >= MAX_NAME_SIZE) {
                throw std::runtime_error("Source name is too long: " + src_name);
            }
            if (dst_name.size() >= MAX_NAME_SIZE) {
                throw std::runtime_error("Destination name is too long: " + dst_name);
            }

            uint32_t src_ip4 = 0;
            bool src_ip_dyn = false;
            if (src_addr == "-" || src_addr == "dynamic") {
                src_ip_dyn = true;
            } else {
                src_ip4 = str_to_ip4(src_addr);
            }

            uint32_t dst_ip4 = 0;
            bool dst_ip_dyn = false;
            if (dst_addr == "-" || dst_addr == "dynamic") {
                dst_ip_dyn = true;
            } else {
                dst_ip4 = str_to_ip4(dst_addr);
            }

            Path4 &path = sender.paths4_vec.emplace_back();
            memset(&path, 0, sizeof(path));
            strcpy(path.src_name, src_name.c_str());
            strcpy(path.dst_name, dst_name.c_str());
            path.src_ip4 = src_ip4;
            path.dst_ip4 = dst_ip4;
            path.src_ip_dyn = src_ip_dyn;
            path.dst_ip_dyn = dst_ip_dyn;
        } else if (cmd == "path6") {
            std::string src_name;
            std::string src_addr;
            std::string dst_name;
            std::string dst_addr;

            iss >> src_name;
            iss >> src_addr;
            iss >> dst_name;
            iss >> dst_addr;

            if (src_name.size() >= MAX_NAME_SIZE) {
                throw std::runtime_error("Source name is too long: " + src_name);
            }
            if (dst_name.size() >= MAX_NAME_SIZE) {
                throw std::runtime_error("Destination name is too long: " + dst_name);
            }

            uint8_t src_ip6[16] = {0};
            bool src_ip_dyn = false;
            if (src_addr == "-" || src_addr == "dynamic") {
                src_ip_dyn = true;
            } else {
                str_to_ip6(src_ip6, src_addr);
            }

            uint8_t dst_ip6[16] = {0};
            bool dst_ip_dyn = false;
            if (dst_addr == "-" || dst_addr == "dynamic") {
                dst_ip_dyn = true;
            } else {
                str_to_ip6(dst_ip6, dst_addr);
            }

            Path6 &path = sender.paths6_vec.emplace_back();
            memset(&path, 0, sizeof(path));
            strcpy(path.src_name, src_name.c_str());
            strcpy(path.dst_name, dst_name.c_str());
            memcpy(path.src_ip6, src_ip6, 16);
            memcpy(path.dst_ip6, dst_ip6, 16);
            path.src_ip_dyn = src_ip_dyn;
            path.dst_ip_dyn = dst_ip_dyn;
        } else if (cmd != "" && cmd[0] != '#') {
            throw std::runtime_error("Unknown option: " + cmd);
        }
    }
    if (!file.eof()) {
        throw std::system_error(errno, std::system_category(), "Failed to read");
    }

    if (sender.ports_count < 1 || sender.ports_count > 65536) {
        throw std::runtime_error("Invalid ports_count: " + std::to_string(sender.ports_count));
    } else if (sender.src_port < 0 || sender.src_port > 65535 - sender.ports_count + 1) {
        throw std::runtime_error("Invalid src_port: " + std::to_string(sender.src_port));
    } else if (sender.dst_port < 0 || sender.dst_port > 65535 - sender.ports_count + 1) {
        throw std::runtime_error("Invalid dst_port: " + std::to_string(sender.dst_port));
    } else if (sender.packet_size <= 40 + 20 + 96) {  // IP[46]+[TCP,UDP,ICMP]+PacketFormat
        throw std::runtime_error("Invalid packet_size: " + std::to_string(sender.packet_size));
    } else if (sender.interval < std::chrono::milliseconds(10)) {
        throw std::runtime_error("Invalid interval: " + std::to_string(sender.interval.count()) + "ns");
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
    sender.interval = std::chrono::milliseconds(100);
    receiver.dev = "eth0";

    // Read configuration files.
    for (int i = 1; i < argc; i++) {
        try {
            read_configuration(argv[i]);
        } catch (const std::exception &e) {
            std::cerr << "Error reading configuration file: " << argv[i] << ": " << e.what() << std::endl;
            return 1;
        }
    }

    // Open socket and network device.
    try {
        sender.index();
        sender.open();
        receiver.open();
        metrics.open();
        switch_user_and_group(cf.user, cf.group);
    } catch (const std::exception &e) {
        std::cerr << "Error during initialization: " << e.what() << std::endl;
        return 1;
    }

    // Start running.
    std::thread addrs_thread(addrs_thread_main);
    std::thread sender_thread(sender_thread_main);
    std::thread metrics_thread(metrics_thread_main);
    std::thread receiver_thread(receiver_thread_main);

    stats_main();
    return 1;
}
