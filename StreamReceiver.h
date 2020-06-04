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


#define SOCK_ERR -1
#define HEADER_LEN sizeof(uint16_t) * 2 // 4 octets
#define RADIOS_SCANNING_TIME_MILI 500


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
    struct in_addr bcast_addr;

    public:
    StreamReceiver(const char* bcast_addr_raw, uint16_t bcast_port, int bcast_timeout, int max_msg_len) : 
        bcast_port(bcast_port), bcast_timeout(bcast_timeout),
        bcast_sock(SOCK_ERR), buffer(max_msg_len, 0), buff_start(0), buff_end(0) {
            if (inet_aton(bcast_addr_raw, &bcast_addr) == 0)
                throw InvalidAddrException();
            set_up_sock();
        }

    ~StreamReceiver() {
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
        if (len > buff_freebytes())
            return false;
        
        content = std::string(buff_ptr(buff_start), len);
        type = (header_type) type_raw;
        buff_start += len;
        return true;
    }

    public:
    std::vector<radio> get_radios() noexcept(false) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(bcast_port);
        addr.sin_addr = bcast_addr;

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

};

#endif /* F89E38BF_41CF_4DC6_8045_4BB5CB7C78B9 */
