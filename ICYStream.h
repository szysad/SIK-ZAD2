#ifndef C5C89C9B_23A9_48C0_91D6_7DE862D0FDA0
#define C5C89C9B_23A9_48C0_91D6_7DE862D0FDA0

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
#include <cassert>
#include <signal.h>
#include <functional>


#define INIT_BUFFER_SIZE 4096
#define MILI 1000
#define READ_ATTEMPTS 3
#define WAIT_MILI_AFTER_ERR 200
#define BUFF_EXPANTION 2
#define RESPONSE_LINE "RESPONSE_LINE"
#define RESPONSE_CODE_OK 200
#define METAINT_HEADER_KEY "ICY-METAINT"
#define METADATA_SIZE_RATIO 16

#define SNPRINTF_UPDATE(last_read, free_b, written_b, ...) {    int tmp;\
                                                                tmp = snprintf(last_read, free_b, __VA_ARGS__);\
                                                                if (tmp < 0 || tmp > free_b) throw BufferTooSmallToContainRequestException();\
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

struct ResponseCodeNot200Exception : public ICYStramException {
    const char* what() const throw() {
        return "ResponseCodeNot200Exception";
    }
};

struct HeaderWrongSyntacException : public ICYStramException {
    const char* what() const throw() {
        return "HeaderWrongSyntacException";
    }
};

struct ICYMetaIntInvalidValueException : public ICYStramException {
    const char* what() const throw() {
        return "ICYMetaIntInvalidValueException";
    }
};

struct SystemCallInterruptionException : public ICYStramException {
    const char* what() const throw() {
        return "SystemCallInterruptionException";
    }
};

struct BufferTooSmallToContainRequestException : public ICYStramException {
    const char* what() const throw() {
        return "BufferTooSmallToContainRequestException";
    }
};

struct StreamDataAccesException : public ICYStramException {
    const char* what() const throw() {
        return "StreamDataAccesException";
    }
};

/* if return value is true, stream processing should be stopped
    data points at start of data buffer to be accesed,
    len is number of bytes of data to be accesed */
using data_accesor = std::function<bool(const char* data, int len)>;


class ICYStream {
    
    std::string port;
    std::string hostname;
    int buff_size;
    std::string resource;
    int timeout;
    bool header_fields_set;
    int sockfd;
    sig_atomic_t stop_processing; // change it outside the class to stop processing
    char *buffer;
    char *last_read;
    char *last_processed;
    std::map<std::string, std::string> header_fields;

    public:
    ICYStream(const std::string &hostname, const std::string &port, const std::string &resource, int timeout, sig_atomic_t &stop_p) : port(port), hostname(hostname),
        buff_size(INIT_BUFFER_SIZE), resource(resource), timeout(timeout), header_fields_set(false), sockfd(-1), stop_processing(stop_p) {
            buffer = new char[INIT_BUFFER_SIZE];
            last_read = last_processed = buffer;
        }
    ~ICYStream() {
        delete [] buffer;
        if (sockfd != -1)
            close(sockfd);
    }

    private:
    int set_up_conn(std::string addr, std::string port) noexcept(false) {
        struct addrinfo addr_hints, *addr_result;
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (sock < 0) throw ConnectionCreationErrorException();

        memset(&addr_hints, 0, sizeof(struct addrinfo));
        addr_hints.ai_flags = 0;
        addr_hints.ai_family = AF_INET;
        addr_hints.ai_socktype = SOCK_STREAM;
        addr_hints.ai_protocol = IPPROTO_TCP;
        
        int rc = getaddrinfo(addr.c_str(), port.c_str(), &addr_hints, &addr_result);
        if (rc != 0) {
            throw ConnectionCreationErrorException();
        }

        rc = connect(sock, addr_result->ai_addr, addr_result->ai_addrlen);
        freeaddrinfo(addr_result);
        if (rc == -1)
            throw ConnectionCreationErrorException();

        sockfd = sock;

        return sock;
    }

    int buff_freebytes() {
        int already_processed_or_read = last_read - buffer;
        return buff_size - already_processed_or_read - 1;
    }

    void reset_pointers() {
        last_processed = buffer;
        last_read = buffer;
    }

    int request_to_buff(bool request_metadata) noexcept(false) {
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

    /* use after every 'last_processed' update */
    void swap_buffer() {
        int already_processed = last_processed - buffer;
        int not_processed = last_read - last_processed;
        if (not_processed == 0) { // we can just reset pointers
            reset_pointers();
            return;
        }
        memmove(buffer, buffer + already_processed, not_processed);
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
        while (last_processed + 1 + i < last_read) { // TODO: SIMPLIFY (can be done without +1 in while)
            if (last_processed[i] == '\r' && last_processed[i + 1] == '\n') {
                rn_end = last_processed + i + 2;
                break;
            }
            i++;
        }
        return rn_end;
    }

    int read_from_sock(struct pollfd pollfd[1]) noexcept(false) {
        int read_errs = 0;
        if (poll(pollfd, 1, timeout * MILI) != 1) {
            /* singal call interupted hopefully by user sending signal,
            if wanted to do properly go multithread */
            if (errno == EINTR) {
                errno = 0;
                throw SystemCallInterruptionException();
            }
            throw ConnectionTimedOutException();
        }

        int r = read(pollfd->fd, last_read, buff_freebytes() - 1); // -1 to leave one byte at end for safety
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
        return r;
    }


    char* read_untill_found_rn(struct pollfd pollfd[1]) noexcept(false) {
        char *rn_end = nullptr;
        while (rn_end == nullptr) {
            rn_end = find_next_rnend();
            if (rn_end == nullptr) {
                if (buff_freebytes() == 0) {
                    realloc_buffer();
                }
                read_from_sock(pollfd);
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

    void process_header(struct pollfd pollfd[1]) noexcept(false) {
        int line_len = 16; // whatever bigger then 0
        std::map<std::string, std::string> h_fields;
        while (line_len > 0) {
            char *eorn = read_untill_found_rn(pollfd);
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

    std::string header_data_stringify(std::map<std::string, std::string> &h_fields) {
        std::string str;
        for (auto it = h_fields.begin(); it != h_fields.end(); it++) {
            str.append(it->first + " : " + it->second + "\n");
        }
        return str;
    }

    int get_response_status(std::map<std::string, std::string> &h_fields) {
        std::regex re(" +([0-9]{3}) +[a-zA-Z]+");
        std::smatch code_match;
        try {
            const std::string res_line = h_fields.at(RESPONSE_LINE);
            if (std::regex_search(res_line, code_match, re))
                return std::stoi(code_match.str(1)); // 0 woudld mean whole matching string, 1 is first captured group

            throw HeaderWrongSyntacException(); // it can be whatever, looks bad but whatever
        } catch (...) {
            throw HeaderWrongSyntacException();
        }
    }

    /* if icy-metaint header is not included it returns 0 */
    int get_metaint(std::map<std::string, std::string> &h_fields) {
        try {
            const std::string metaint = h_fields.at(METAINT_HEADER_KEY);
            return std::stoi(metaint);
        } catch(const std::out_of_range &e) { // metaint not given
            return 0;
        } catch (...) {
            throw HeaderWrongSyntacException();
        }
    }

    void stop_stream_processing() {
        stop_processing = true;
    }

    /* reads at least n bytes, pushes last_processed n bytes forward, and writes n bytes to FILE */
    void acces_n_bytes(struct pollfd pollfd[1], int n, data_accesor accesor) noexcept(false) {
        int processed = 0;
        while (processed < n) {
            read_from_sock(pollfd);
            int not_processed = last_read - last_processed;
            int to_acces = std::min(n - processed, not_processed);
            try {
                if (accesor(last_processed, to_acces))
                    stop_stream_processing();
            } catch (...) {
                throw StreamDataAccesException();
            }
            processed += to_acces;
            last_processed += to_acces;
            swap_buffer();
        }
    }

    void process_stream_content(struct pollfd pollfd[1], data_accesor accesor) noexcept(false) {
        while (!stop_processing) {
            read_from_sock(pollfd);
            int not_processed = last_read - last_processed;
            try {
                if (accesor(last_processed, not_processed))
                    stop_stream_processing();
            } catch (...) {
                throw StreamDataAccesException();
            }
            last_processed += not_processed;
            swap_buffer();
        }
    }

    void process_stream_content(struct pollfd pollfd[1], int metaint, data_accesor mp3_acc, data_accesor meta_acc) noexcept(false) {
        while (!stop_processing) {
            /* process audio data */
            acces_n_bytes(pollfd, metaint, mp3_acc);
            /* read data so 'last_processed' is guaranted to point at valid data */
            read_from_sock(pollfd);
            /* now last_processed should point to length_byte */
            /* multiplication comes from SHOUTcast documentation */
            int metadata_len = ((uint8_t) *last_processed) * METADATA_SIZE_RATIO;
            last_processed++; /* push 'last_processed' past metadata_len byte */
            swap_buffer();
            acces_n_bytes(pollfd, metadata_len, meta_acc);
        }
    }

    public:
    /* will throw if used before 'process_stream' */
    std::map<std::string, std::string> get_header_fields() noexcept(false) {
        if (header_fields_set == false)
            throw DataNotReceivedYetException();
        
        return header_fields;
    }

    /* sends mp3 data to stdout, metadata includeing header to stderr, blocks for streaming duration */
    void process_stream(bool request_metadata, data_accesor mp3_acc, data_accesor meta_acc) noexcept(false) {
        struct pollfd pollfd[1];
        int sock = set_up_conn(hostname, port);
        pollfd->fd = sock;
        pollfd->events = POLLIN;
        pollfd->revents = 0;

        try {
            int req_size = request_to_buff(request_metadata);
            send_to_sock(sock, req_size);
            clear_buffer();
            process_header(pollfd);

            int response_code = get_response_status(header_fields);
            int metaint = get_metaint(header_fields);
            if (response_code != RESPONSE_CODE_OK)
                throw ResponseCodeNot200Exception();
            if (metaint < 0)
                throw ICYMetaIntInvalidValueException();


            std::string header_str = header_data_stringify(header_fields);
            meta_acc(header_str.c_str(), header_str.length());

            if (metaint == 0)
                process_stream_content(pollfd, mp3_acc);
            else
                process_stream_content(pollfd, metaint, mp3_acc, meta_acc);

        } catch (SystemCallInterruptionException &e) {
            // Dont throw hopefully its user intended
        } catch (ICYStramException &e) {
            throw;
        }
    }
};

#endif /* C5C89C9B_23A9_48C0_91D6_7DE862D0FDA0 */
