#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <map>
#include <regex>
#include <exception>
#include <thread>
#include <chrono>
#include <algorithm>

#define INIT_BUFFER_SIZE 4056
#define MILI 1000
#define READ_ATTEMPTS 3
#define WAIT_MILI_AFTER_ERR 200
#define BUFF_EXPANTION 2
#define RESPONSE_LINE "RESPONSE_LINE"

#define SNPRINTF_UPDATE(last_read, free_b, written_b, ...) {    int tmp;\
                                                                tmp = snprintf(last_read, free_b, __VA_ARGS__);\
                                                                if (tmp < 0 || tmp > free_b) throw "snprintf fail";\
                                                                last_read += tmp;\
                                                                free_b -= tmp;\
                                                                written_b += tmp; }

struct ICYStramException : public std::exception {
    virtual const char* what() const throw() {
        return "EndOfStreamException";
    }
};

struct EndOfStreamException : public ICYStramException {
    const char* what() const throw() {
        return "EndOfStreamException";
    }
};

struct StreamErrorException : public ICYStramException {
    const char* what() const throw() {
        return "StreamErrorException";
    }
};

struct ConnectionTimedOutException : public ICYStramException {
    const char* what() const throw() {
        return "ConnectionTimedOutException";
    }
};

struct MemoryErrorException : public ICYStramException {
    const char* what() const throw() {
        return "MemoryErrorException";
    }
};

struct ConnectionCreationErrorException : public ICYStramException {
    const char* what() const throw() {
        return "ConnectionCreationErrorException";
    }
};

struct DataNotReceivedYetException : public ICYStramException {
    const char* what() const throw() {
        return "DataNotReceivedYetException";
    }
};

class ICYStream {
    
    std::string port;
    std::string hostname;
    int buff_size;
    std::string resource;
    int timeout;
    bool header_fields_set;
    char *buffer;
    char *last_read;
    char *last_processed;
    std::map<std::string, std::string> header_fields;

    public:
    ICYStream(std::string hostname, std::string port, std::string resource, int timeout) : port(port), hostname(hostname),
        buff_size(INIT_BUFFER_SIZE), resource(resource), timeout(timeout), header_fields_set(false) {
            buffer = new char[INIT_BUFFER_SIZE];
            last_read = last_processed = buffer;
        }
    ~ICYStream() {
        delete [] buffer;
    }

    private:
    int set_up_conn(std::string addr, std::string port) noexcept(false) {
        struct addrinfo addr_hints, *addr_result;
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        if (sock < 0) throw ConnectionCreationErrorException();

        memset(&addr_hints, 0, sizeof(struct addrinfo));
        addr_hints.ai_flags = 0;
        addr_hints.ai_family = AF_INET;
        addr_hints.ai_socktype = SOCK_STREAM;
        addr_hints.ai_protocol = IPPROTO_TCP;
        
        int rc = getaddrinfo(addr.c_str(), port.c_str(), &addr_hints, &addr_result);
        if (rc != 0) {
            freeaddrinfo(addr_result);
            throw ConnectionCreationErrorException();
        }

        rc = connect(sock, addr_result->ai_addr, addr_result->ai_addrlen);
        freeaddrinfo(addr_result);
        if (rc == -1)
            throw ConnectionCreationErrorException();

        return sock;
    }

    int buff_freebytes() {
        return buff_size - (last_read - buffer);
    }

    void reset_pointers() {
        last_processed = buffer;
        last_read = buffer;
    }

    int request_to_buff(bool request_metadata) {
        int written_b = 0;
        int free_b = buff_freebytes();

        SNPRINTF_UPDATE(last_read, free_b, written_b, "GET %s HTTP/1.0\r\n", resource.c_str())
        SNPRINTF_UPDATE(last_read, free_b, written_b, "HOST: %s:%s\r\n", hostname.c_str(), port.c_str())
        SNPRINTF_UPDATE(last_read, free_b, written_b, "ACCEPT: */*\r\n")
        if (request_metadata)
            SNPRINTF_UPDATE(last_read, free_b, written_b, "ICY-METADATA:1\r\n")   
        SNPRINTF_UPDATE(last_read, free_b, written_b, "CONNECTION: CLOSE\r\n\r\n")

        return written_b;
    }

    void realloc_buffer() {
        int last_read_pos = last_read - buffer;
        int last_processed_pos = last_processed - buffer;

        buffer = (char*) realloc(buffer, buff_size * BUFF_EXPANTION);
        if (buffer == nullptr)
            throw MemoryErrorException();
        
        last_read = buffer + last_read_pos;
        last_processed = buffer + last_processed_pos;
        buff_size *= BUFF_EXPANTION;
    }

    void swap_buffer() {
        int already_processed = last_processed - buffer;
        int not_processed = last_read - last_processed;
        memmove(buffer, buffer + already_processed, buff_size - already_processed);
        last_processed = buffer;
        last_read = buffer + not_processed;
    }

    void clear_buffer() {
        memset(buffer, 0, buff_size);
        last_processed = last_read = buffer;
    }

    void send_to_sock(int sock, int bytes) noexcept(false) {
        int r, send_bytes = 0;
        while (send_bytes < bytes){
            r = write(sock, buffer, bytes);
            if (r < 0)
                throw StreamErrorException();
            send_bytes += r;
        }
    }

    /* needs at least one free byte at end of buffer */
    char* find_next_rnend() {
        int i = 0;
        char *rn_end = nullptr;
        while (last_processed + 1 + i < last_read) {
            if (last_processed[i] == '\r' && last_processed[i + 1] == '\n') {
                rn_end = last_processed + i + 2;
                break;
            }
            i++;
        }
        return rn_end;
    }

    void read_from_sock(int sock, struct pollfd pollfd[1], int n) noexcept(false) {
        int read_errs = 0;
        if (poll(pollfd, 1, timeout * MILI) != 1)
            throw ConnectionTimedOutException();

        int r = read(sock, last_read, n);
        if (r == 0)
            throw EndOfStreamException();
        if (r < 0) {
            if (read_errs < READ_ATTEMPTS) {
                read_errs++;
                std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_MILI_AFTER_ERR));
            }
            else throw StreamErrorException();
        }
        last_read += r;
    }


    char* read_untill_found_rn(int sock, struct pollfd pollfd[1]) noexcept(false) {
        char *rn_end = nullptr;
        while (rn_end == nullptr) {
            rn_end = find_next_rnend();
            if (rn_end == nullptr) {
                if (buff_freebytes() == 0) {
                    realloc_buffer();
                }
                read_from_sock(sock, pollfd, buff_freebytes() - 1); // -1 for 'find_next_rnend()' safety, can throw
            }
        }
        return rn_end;
    }

    std::string &trim(std::string &s, const char *t = " \t\n") {
        s.erase(s.find_last_not_of(t) + 1);
        s.erase(0, s.find_first_not_of(t));
        return s;
    }

    /* if request line contains ':' will couse trouble */
    void parse_header_line(std::map<std::string, std::string> &map, std::string &line) {
        std::stringstream ss(line);
        std::string segment;
        std::string key, val;

        /* spliting ss by ':' */
        std::getline(ss, key, ':');
        std::getline(ss, val, ':');

        if (val.empty()) {
            map.insert({RESPONSE_LINE, trim(key)});
        } else {
            /* make all keys uppercase */
            std::transform(key.begin(), key.end(), key.begin(), ::toupper);
            map.insert({trim(key), trim(val)});
        }
    }

    void process_header(int sock, struct pollfd pollfd[1]) noexcept(false) {
        int line_len = 16; // whatever bigger then 0
        std::map<std::string, std::string> h_fields;
        while (line_len > 0) {
            char *eorn = read_untill_found_rn(sock, pollfd);
            line_len = eorn - last_processed - 2; // -2 becouse we dont count /r/n
            if (line_len > 0) {
                std::string line(last_processed, line_len);
                parse_header_line(h_fields, line);
            }
            last_processed += line_len + 2; // +2 becouse we want last_processed pushed one byte after /r/n
            swap_buffer();
        }
        header_fields_set = true;
        header_fields = h_fields;
    }

    public:
    /* will throw if used before 'streamContent' */
    std::map<std::string, std::string> get_header_fields() noexcept(false) {
        if (header_fields_set == false)
            throw DataNotReceivedYetException();
        
        return header_fields;
    }

    void streamContent(int fd_data_output, int fd_meta_output, bool request_metadata) noexcept(false) {
        struct pollfd pollfd[1];
        int sock = set_up_conn(hostname, port);
        pollfd->fd = sock;
        pollfd->events = POLLIN;
        pollfd->revents = 0;

        try {
            int req_size = request_to_buff(request_metadata);
            send_to_sock(sock, req_size);
            clear_buffer();
            process_header(sock, pollfd);
            //TODO: rest
        } catch (ICYStramException &e) {
            close(sock);
            throw;
        }
    }
};