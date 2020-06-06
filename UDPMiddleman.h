#ifndef E0B4F753_4728_4630_AEBD_B4B78AE118F8
#define E0B4F753_4728_4630_AEBD_B4B78AE118F8

#include <string>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <map>
#include <time.h>
#include <iostream>
#include <fcntl.h>
#include <ctime>
#include <utility>

#define HEADER_LEN sizeof(uint16_t) * 2 // 4 octets
#define MULTICAST_ADDR_NOT_GIVEN ""
#define INIT_BUFFER_SIZE 4096
#define SOCKET_RET_ERR -1
#define MAX_CLIENT_REQ_PER_ITER 5
#define ERRORS_THRESHOLD 128
#define BUFFER_EXPANSION_RATIO 2

#define ERR_CNT_INC_OR_THROW(err_cnt, max_cnt) { if (err_cnt > max_cnt) throw; err_cnt++; }


struct UDPMiddlemanException : public std::exception {
    virtual const char* what() const throw() {
        return "UDPMiddlemanException";
    }
};

struct ConnectionCreationException : public UDPMiddlemanException {
    virtual const char* what() const throw() {
        return "ConnectionCreationException";
    }
};

struct ReadErrorException : public UDPMiddlemanException {
    virtual const char* what() const throw() {
        return "ReadErrorException";
    }
};

struct SendErrorException : public UDPMiddlemanException {
    virtual const char* what() const throw() {
        return "SendErrorException";
    }
};

struct TimeErrorException : public UDPMiddlemanException {
    virtual const char* what() const throw() {
        return "TimeErrorException";
    }
};

struct InvalidRequestException : public UDPMiddlemanException {
    virtual const char* what() const throw() {
        return "InvalidRequestException";
    }
};

struct NotEnoughtBufferSpaceException : public UDPMiddlemanException {
    virtual const char* what() const throw() {
        return "NotEnoughtBufferSpaceException";
    }
};

struct ResponseBuildingErrorException : public UDPMiddlemanException {
    virtual const char* what() const throw() {
        return "ResponseBuildingErrorException";
    }
};

struct MemoryAllocationErrorException : public UDPMiddlemanException {
    virtual const char* what() const throw() {
        return "MemoryAllocationErrorException";
    }
};

//TODO put in anonyomus namespace
enum header_type : uint16_t {DISCOVER = 1, IAM = 2, KEEPALIVE = 3, AUDIO = 4, METADATA = 6};
using header = std::pair<header_type, uint16_t>; /* <type, length> */
enum client_state {TRANSMISION_NOT_STARTED, TRANSMISION_STARTED};
using client_id = std::pair<uint32_t, uint32_t>; /* <addr, port in network order> */
using client_data = std::pair<time_t, client_state>; /* <last time data was received, state> */
using client_map = std::map<client_id, client_data>;

class UDPMIddleman {

    std::string local_port;
    std::string mulitcast_addr;
    std::string desc;
    int timeout;
    int sock;
    char *buffer;
    char *last_processed;
    char *last_read;
    int buffer_size;
    client_map clients;

    public:
    UDPMIddleman(std::string local_port, std::string mulitcast_addr, int timeout, std::string desc) : 
        local_port(local_port), mulitcast_addr(mulitcast_addr), desc(desc), timeout(timeout), sock(SOCKET_RET_ERR) {
            buffer = new char[INIT_BUFFER_SIZE];
            last_processed = last_read = buffer;
            buffer_size = INIT_BUFFER_SIZE;
            sock = set_up_conn();
        }

    ~UDPMIddleman() {
        delete [] buffer;
        if (sock != SOCKET_RET_ERR) {
            close(sock);
        }
    }

    private:
    int set_up_conn() noexcept(false) {
        struct ip_mreqn ip_memship;
        struct sockaddr_in local_addr;
        int optval, sockfd;

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == SOCKET_RET_ERR)
            throw ConnectionCreationException();

        /* turn nonblocking mode on for sock */
        if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0)
            throw ConnectionCreationException();

        if (mulitcast_addr != MULTICAST_ADDR_NOT_GIVEN) {
            ip_memship.imr_address.s_addr = htonl(INADDR_ANY);
            ip_memship.imr_ifindex = 0;
            if (inet_aton(mulitcast_addr.c_str(), &ip_memship.imr_multiaddr) == 0)
                throw ConnectionCreationException();

            if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*) &ip_memship, sizeof(ip_memship)) == -1)
                throw ConnectionCreationException();
        }

        /* allow broadcast receiving / sending */
        optval = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (void*) &optval, sizeof(optval)) == -1)
            throw ConnectionCreationException();

        local_addr.sin_family = AF_INET;
        local_addr.sin_port = htons(std::stoi(local_port));
        local_addr.sin_addr.s_addr = htons(INADDR_ANY);

        if (bind(sockfd, (sockaddr*) &local_addr, sizeof(local_addr)) == -1)
            throw ConnectionCreationException();

        return sockfd;
    }

    void realloc_buffer() noexcept(false) {
        char *new_buff = new char[buffer_size * BUFFER_EXPANSION_RATIO];
        int last_processed_pos = last_processed - buffer;
        int last_read_pos = last_read - buffer;
        if (new_buff == nullptr)
            throw MemoryAllocationErrorException();

        memcpy(new_buff, buffer, buffer_size);
        delete [] buffer;

        buffer_size *= BUFFER_EXPANSION_RATIO;
        buffer = new_buff;
        last_processed = buffer + last_processed_pos;
        last_read = buffer + last_read_pos;
    }

    int buffer_freebytes() {
        return buffer_size - (last_read - buffer) - 1;
    }

    /* if something is read return true, sets id and update buffer pointers */
    bool try_receive_datagram(client_id &id) noexcept(false) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        // buffer_freebytes() - 1, for safety, last_read is pushed one byte after actual last_read byte
        int r = recvfrom(sock, last_processed, buffer_freebytes() - 1, 0, (struct sockaddr*) &client_addr, &addr_len);
        if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) //nothing to read
                return false;
            throw ReadErrorException();
        }
        last_read = last_processed + r;
        id.first = client_addr.sin_addr.s_addr;
        id.second = client_addr.sin_port;
        return true;
    }

    /* tries to send buffer content from range [last_processed, last_read), returns true if succesful*/
    bool try_send_datagram_to(const client_id &id) noexcept(false) {
        struct sockaddr_in client_addr;

        client_addr.sin_family = AF_INET;
        client_addr.sin_port = id.second;
        client_addr.sin_addr.s_addr = id.first;
        char *last_processed_starting_val = last_processed;
        int r = sendto(sock, last_processed, last_read - last_processed, 0, (struct sockaddr*) &client_addr, sizeof(client_addr));
        if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { // send would block kerner buffer or whatever
                last_processed = last_processed_starting_val;
                return false;
            }
            throw SendErrorException();
        }
        last_processed += r;
        return true;
    }

    void clear_buffer() {
        last_read = last_processed = buffer;
    }

    /* free bytes after 'last_processed' */
    int buff_free_to_write() {
        return buffer_size - (last_processed - buffer) - 1;
    }

    void update_client_data(const client_id &client) noexcept(false) {
        time_t time_now = std::time(nullptr);
        if (time_now == -1)
            throw TimeErrorException();
        auto it = clients.find(client);
        if (it == clients.end()) {
            clients.insert({client, {time_now, TRANSMISION_NOT_STARTED}});
        } else {
            // just update time
            it->second.first = time_now;
        }
    }

    header process_request() noexcept(false) {
        if (last_read - last_processed < static_cast<int>(HEADER_LEN)) // message too short
            throw InvalidRequestException();
        header req_header;
        uint16_t type, len;
        memcpy((void*) &type, last_processed, sizeof(uint16_t));
        last_processed += sizeof(uint16_t);
        memcpy((void*) &len, last_processed, sizeof(uint16_t));
        last_processed += sizeof(uint16_t);
        
        // well I should be more consistent with C or C++ casting style
        req_header.first = static_cast<header_type>(ntohs(type));
        req_header.second = ntohs(len);

        last_processed = last_read;
        return req_header;
    }

    void build_header(const header &h) noexcept(false) {
        if (buffer_freebytes() < static_cast<int>(HEADER_LEN))
            throw NotEnoughtBufferSpaceException();
        
        mempcpy(last_read, &h.first, sizeof(header_type));
        last_read += sizeof(header_type);
        memcpy(last_read, &h.second, sizeof(uint16_t));
        last_read += sizeof(uint16_t);
    }

    void build_IAM_res(std::string &rsp) noexcept(false) {
        if (buffer_freebytes() < static_cast<int>(HEADER_LEN))
            throw NotEnoughtBufferSpaceException();

        int msg_len = static_cast<int>(rsp.length());
        build_header({IAM, msg_len});
        memcpy(last_read, rsp.c_str(), msg_len);
        last_read += msg_len;
    }

    void delete_timeouted_clients() noexcept(false) {
        time_t time = std::time(nullptr);
        if (time == -1)
            throw TimeErrorException();

        for (auto it = clients.begin(); it != clients.end(); /* inc not here */) {
            double time_diff = difftime(time, it->second.first);
            if (time_diff > static_cast<double>(timeout)) {
                it = clients.erase(it);
            } else {
                it++;
            }
        }
    }

    void build_DATA_res(header_type type, const char* data, int data_len) noexcept(false) {
        while (buffer_freebytes() < data_len + static_cast<int>(HEADER_LEN))
            realloc_buffer();
        
        build_header({type, data_len});
        memcpy(last_read, data, data_len);
        last_read += data_len;
    }


    void broadcast_iteration(header_type type, const char *data, int data_len) {
        client_id client;
        int preocessed_requests = 0;
        static int errors = 0;

        try {
            while (preocessed_requests < MAX_CLIENT_REQ_PER_ITER) {
                if (!try_receive_datagram(client)) // no pending requests
                    break;
                header h = process_request();
                update_client_data(client);
                if (h.first == DISCOVER) {
                    clear_buffer();
                    // wont throw, becouse update_client_data added him to clients
                    auto data_it = clients.find(client);
                    if (data_it->second.second == TRANSMISION_NOT_STARTED) {
                        data_it->second.second = TRANSMISION_STARTED;
                        build_IAM_res(desc);
                        try_send_datagram_to(client);
                    }
                }
                preocessed_requests++;
            }
        } catch (...) {
            ERR_CNT_INC_OR_THROW(errors, ERRORS_THRESHOLD)
        }
        
        delete_timeouted_clients();
        clear_buffer();
        build_DATA_res(type, data, data_len);
        
        for(auto it = clients.begin(); it != clients.end(); it++) {
            char* org_last_proc = last_processed;
            try {
                if (it->second.second == TRANSMISION_STARTED) 
                    try_send_datagram_to(it->first);
            } catch (...) {
                ERR_CNT_INC_OR_THROW(errors, ERRORS_THRESHOLD)
            }
            // lil dirty but reset last_processed
            last_processed = org_last_proc;
        }
        clear_buffer();
    }

    public:
    void broadcast_audio_iteration(const char* data, int data_len) {
        broadcast_iteration(AUDIO, data, data_len);
    }

    void broadcast_meta_iteration(const char* data, int data_len) {
        broadcast_iteration(METADATA, data, data_len);
    }
};

#endif /* E0B4F753_4728_4630_AEBD_B4B78AE118F8 */
