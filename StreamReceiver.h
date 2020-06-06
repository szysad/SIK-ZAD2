#ifndef F89E38BF_41CF_4DC6_8045_4BB5CB7C78B9
#define F89E38BF_41CF_4DC6_8045_4BB5CB7C78B9

#include <string>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <chrono>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>


#define SOCK_ERR -1
#define HEADER_LEN sizeof(uint16_t) * 2 // 4 octets
#define RADIOS_SCANNING_TIME_MILI 500
#define CONN_TRIES 5
#define MAX_BUF_SIZE 8192


struct StreamReceiverException : public std::exception {
    virtual const char* what() const throw() {
        return "StreamReceiverException";
    }
};

struct ConnectionCreationErrorException : public StreamReceiverException {
    virtual const char* what() const throw() {
        return "ConnectionCreationErrorException";
    }
};

struct SendErrorException : public StreamReceiverException {
    virtual const char* what() const throw() {
        return "SendErrorException";
    }
};

struct InvalidAddrException : public StreamReceiverException {
    virtual const char* what() const throw() {
        return "InvalidAddrException";
    }
};

struct ReadErrorException : public StreamReceiverException {
    virtual const char* what() const throw() {
        return "ReadErrorException";
    }
};

struct BufferTooSmallException : public StreamReceiverException {
    virtual const char* what() const throw() {
        return "BufferTooSmallException";
    }
};

    using radio = std::pair<std::string, sockaddr_in>;
    using data_accesor = std::function<void(std::string &data)>;
namespace {
    enum header_type : uint16_t {DISCOVER = 1, IAM = 2, KEEPALIVE = 3, AUDIO = 4, METADATA = 6};
    std::vector<uint16_t> header_type_vals = {DISCOVER, IAM, KEEPALIVE, AUDIO, METADATA};
}

class StreamReceiver {

    uint16_t bcast_port; // UDP
    int bcast_timeout;
    int bcast_sock;
    std::vector<char> buffer;
    int buff_start;
    int buff_end;
    std::atomic_bool connected;
    struct in_addr bcast_addr;
    std::thread conn_keeper;
    std::mutex m;

    public:
    StreamReceiver(const char* bcast_addr_raw, uint16_t bcast_port, int bcast_timeout) : 
        bcast_port(bcast_port), bcast_timeout(bcast_timeout), bcast_sock(SOCK_ERR),
        buffer(MAX_BUF_SIZE, 0), buff_start(0), buff_end(0), connected(false) {
            if (inet_aton(bcast_addr_raw, &bcast_addr) == 0)
                throw InvalidAddrException();
            set_up_sock();
        }

    ~StreamReceiver() {
        disconnect();
        if (bcast_sock != SOCK_ERR)
            close(bcast_sock);
    }

    private:
    void set_up_sock() {
        struct ip_mreqn ip_memship;
        struct sockaddr_in local_addr;
        int optval, sockfd;

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == SOCK_ERR)
            throw ConnectionCreationErrorException();

        /* turn nonblocking mode on for sock */
        if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0)
            throw ConnectionCreationErrorException();

        // allow multicast
        ip_memship.imr_address.s_addr = htonl(INADDR_ANY);
        ip_memship.imr_multiaddr = bcast_addr;
        ip_memship.imr_ifindex = 0;

        if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*) &ip_memship, sizeof(ip_memship)) == -1) {
            throw ConnectionCreationErrorException();
        }

        /* allow broadcast receiving / sending */
        optval = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (void*) &optval, sizeof(optval)) == -1)
            throw ConnectionCreationErrorException();

        local_addr.sin_family = AF_INET;
        local_addr.sin_port = 0; // whatever port
        local_addr.sin_addr.s_addr = htons(INADDR_ANY);

        if (bind(sockfd, (sockaddr*) &local_addr, sizeof(local_addr)) == -1)
            throw ConnectionCreationErrorException();

        bcast_sock = sockfd;
    }

    inline int buff_freebytes() {
        return buffer.size() - buff_end - 1;
    }

    inline void clear_buffer() {
        buff_end = buff_start = 0;
    }

    // seq fault if buffer is empty
    inline char *buff_ptr(int pos) {
        return &buffer[pos];
    }

    // make sure there is at least HEADER_LEN of free space in buff
    // buff_start must equal buff_end
    void build_HEADER(header_type type, uint16_t len) {
        uint16_t h_type = htons(type);
        uint16_t h_len = htons(len);
        memcpy(buff_ptr(buff_end), &h_type, sizeof(uint16_t));
        buff_end += sizeof(uint16_t);
        memcpy(buff_ptr(buff_end), &h_len, sizeof(uint16_t));
        buff_end += sizeof(uint16_t);
    }

    // sends data from range [buff_start, buff_end)
    bool try_send_msg(const struct sockaddr_in &addr) {
        int to_send = buff_end - buff_start;
        int r = sendto(bcast_sock, buff_ptr(buff_start), to_send, 0, (struct sockaddr*) &addr, sizeof(addr));
        if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) // send would block kerner buffer or whatever
                return false;
            throw SendErrorException();
        }
        return true;
    }

    bool try_receive_msg(struct sockaddr_in &addr) {
        struct sockaddr_in sender_addr;
        socklen_t addr_len = sizeof(sender_addr);
        int r = recvfrom(bcast_sock, buff_ptr(buff_start), buff_freebytes(), 0, (struct sockaddr*) &sender_addr, &addr_len);
        if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) //nothing to read
                return false;
            throw ReadErrorException();
        }
        buff_end = buff_start + r;
        addr = sender_addr;
        return true;
    }

    inline bool is_valid_type(uint16_t type) {
        return (std::find(header_type_vals.begin(), header_type_vals.end(), type) != header_type_vals.end());
    }

    // make sure buffer is cleaned before
    // return vals by reference
    bool parse_msg(header_type &type, std::string &content) {
        uint16_t type_raw, len;
        memcpy(&type_raw, buff_ptr(buff_start), sizeof(uint16_t));
        if (!is_valid_type(type_raw))
            return false;

        buff_start += sizeof(uint16_t);
        memcpy(&len, buff_ptr(buff_start), sizeof(uint16_t));
        buff_start += sizeof(uint16_t);
        if (len > MAX_BUF_SIZE) {
            return false;
        } else if (len > buffer.size() && buffer.size() < MAX_BUF_SIZE) {
            buffer.resize(std::min(static_cast<uint16_t>(MAX_BUF_SIZE), len));
        }
        
        content.assign(buff_ptr(buff_start), len);
        type = (header_type) type_raw;
        buff_start += len;
        return true;
    }

    inline bool cmp_addr(struct sockaddr_in &a1, struct sockaddr_in &a2) {
        bool yes = true;
        yes &= (a1.sin_addr.s_addr == a2.sin_addr.s_addr);
        yes &= (a1.sin_family == a2.sin_family);
        yes &= (a1.sin_port == a2.sin_port);
        return yes;
    }

    void conn_keeper_routine(radio r, data_accesor mp3_acc, data_accesor meta_acc) {
        auto keepalive_t0 = std::chrono::system_clock::now();
        auto timeout_t0 = keepalive_t0;
        while(connected) {
            auto t_now = std::chrono::system_clock::now();
            int64_t t_timeout_diff = std::chrono::duration_cast<std::chrono::seconds>(t_now - timeout_t0).count();
            if (t_timeout_diff >= bcast_timeout) {
                connected = false; 
                break;
            }
            int64_t t_keepalive_diff = std::chrono::duration_cast<std::chrono::seconds>(t_now - keepalive_t0).count();
            header_type type;
            std::string msg;
            { // critical section start
                std::lock_guard<std::mutex> buff_acces(m);
                clear_buffer();
                struct sockaddr_in addr;
                int received;
                try {
                    if (t_keepalive_diff >= bcast_timeout) {
                        keepalive_t0 = std::chrono::system_clock::now();
                        build_HEADER(KEEPALIVE, 0);
                        try {
                            try_send_msg(r.second);
                        } catch (...) {
                            connected = false;
                            break;
                        }
                        clear_buffer();
                    }
                    received = try_receive_msg(addr);
                } catch (...) {
                    connected = false;
                    break;
                }
                // if didnt receive go back;
                if (!received)
                    continue;
                // if not my radio ignore
                if (!cmp_addr(addr, r.second))
                    continue;

                if (!parse_msg(type, msg))
                    continue;
            } // critical section end
            // process message and reset timeout counter
            if (type == AUDIO) mp3_acc(msg);
            else if (type == METADATA) meta_acc(msg);
            timeout_t0 = std::chrono::system_clock::now();
        }
    }

    public:
    std::vector<radio> get_radios() noexcept(false) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(bcast_port);
        addr.sin_addr = bcast_addr;

        const std::lock_guard<std::mutex> buff_acces(m);
        clear_buffer();
        build_HEADER(DISCOVER, 0);
        if (!try_send_msg(addr)) // couldnt send so just return no results
            return std::vector<radio>();

        std::vector<radio> radios;
        header_type type;
        std::string msg;
        int64_t t_diff;
        auto t_started = std::chrono::system_clock::now();

        do {
            clear_buffer();
            bool ok = try_receive_msg(addr);
            ok &= parse_msg(type, msg);
            if (ok && msg.length() > 0 && type == IAM)
                radios.emplace_back(msg, addr);

            auto t_now = std::chrono::system_clock::now();
            t_diff = std::chrono::duration_cast<std::chrono::milliseconds>(t_now - t_started).count();
        } while (t_diff < RADIOS_SCANNING_TIME_MILI);
        
        return radios;
    }

    void disconnect() {
        connected = false;
        if (conn_keeper.joinable())
            conn_keeper.join();
    }

    bool is_connected() {
        return connected;
    }

    void connect_to_radio(radio &r, data_accesor mp3_acc, data_accesor meta_acc) {
        const std::lock_guard<std::mutex> buff_acces(m);
        clear_buffer();
        build_HEADER(DISCOVER, 0);
        if (try_send_msg(r.second)) {
            connected = true;
            conn_keeper = std::thread(&StreamReceiver::conn_keeper_routine, this, r, mp3_acc, meta_acc);
        }
    }

};

#endif /* F89E38BF_41CF_4DC6_8045_4BB5CB7C78B9 */
