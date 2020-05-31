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


#define INIT_BUFFER_SIZE 4056
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


class ICYStream {
    
    std::string port;
    std::string hostname;
    int buff_size;
    std::string resource;
    int timeout;
    bool header_fields_set;
    bool keep_processing;
    char *buffer;
    char *last_read;
    char *last_processed;
    std::map<std::string, std::string> header_fields;

    public:
    ICYStream(std::string hostname, std::string port, std::string resource, int timeout) : port(port), hostname(hostname),
        buff_size(INIT_BUFFER_SIZE), resource(resource), timeout(timeout), header_fields_set(false), keep_processing(true) {
            buffer = new char[INIT_BUFFER_SIZE];
            last_read = last_processed = buffer;
        }
    ~ICYStream() {
        delete [] buffer;
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
        int already_processed_or_read = last_read - buffer;
        return buff_size - already_processed_or_read;
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
        std::string before(last_processed, not_processed); // DEBUG
        memmove(buffer, buffer + already_processed, not_processed);
        last_processed = buffer;
        last_read = buffer + not_processed;
        std::string after(last_processed, not_processed); // DEBUG
        assert(before == after); // DEBUG
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
        assert(n <= buff_freebytes() && n > 0); // DEBUG
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

    std::string header_data_stringify(std::map<std::string, std::string> &h_fields) {
        std::string str;
        for (auto it = h_fields.begin(); it != h_fields.end(); it++) {
            str.append(it->first + " : " + it->second + "\n");
        }
        return str;
    }

    int get_response_status(std::map<std::string, std::string> &h_fields) {
        try {
            const std::string res_line = h_fields.at(RESPONSE_LINE);
            return std::stoi(res_line.substr(9, 3)); // 9 becouse len("HTTP/1.x ") == 9;
        } catch (...) {
            throw HeaderWrongSyntacException();
        }
    }

    /* if icy-metaint header is not included it returns 0 */
    int get_metaint(std::map<std::string, std::string> &h_fields) {
        try {
            const std::string metaint = h_fields.at(METAINT_HEADER_KEY);
            return std::stoi(metaint); // 9 becouse len("HTTP/1.x ") == 9;
        } catch(const std::out_of_range &e) {
            return 0;
        } catch (...) {
            throw HeaderWrongSyntacException();
        }
    }

    void write_n_bytes(int sock, struct pollfd pollfd[1], int n, FILE *f) noexcept(false) {
        int processed = 0;
        while (processed < n) {
            read_from_sock(sock, pollfd, buff_freebytes() - 8 /* DEBUG */);
            int not_processed = last_read - last_processed;
            int to_write = std::min(n - processed, not_processed);
            if (f == stderr) { // DEBUG
                int written = fwrite(last_processed, 1, to_write, f);
                if (written != to_write)
                    throw StreamErrorException();
            }
            processed += to_write;
            last_processed += to_write;
            if (f == stderr) {
                printf("%c", *(last_processed - 2));
            }
            swap_buffer();
        }
    }

    void process_stream_content(int sock, struct pollfd pollfd[1]) noexcept(false) {
        while (keep_processing) {
            read_from_sock(sock, pollfd, buff_freebytes());
            int not_processed = last_read - last_processed;
            int written = fwrite(last_processed, 1, not_processed, stdout);
            if (written != not_processed)
                throw StreamErrorException();
            last_processed += not_processed;
            swap_buffer();
        }
    }

    void process_stream_content(int sock, struct pollfd pollfd[1], int metaint) noexcept(false) {
        while (keep_processing) {
            /* process audio data */
            write_n_bytes(sock, pollfd, metaint, stdout);
            /* now last_processed should point to length_byte */
            /* multiplication comes from SHOUTcast documentation */
            int metadata_len = ((uint8_t) *last_processed) * METADATA_SIZE_RATIO;
            last_processed++; /* push last_processed past metadata_len byte */
            assert(last_processed != buffer + buff_size); // DEBUG
            std::cout << "next metadata len = " << metadata_len << std::endl;
            if (metadata_len == 0) { // DEBUG
                printf("%d", *(last_processed - 1));
            }
            write_n_bytes(sock, pollfd, metadata_len, stderr);
        }
    }

    public:
    /* will throw if used before 'streamContent' */
    std::map<std::string, std::string> get_header_fields() noexcept(false) {
        if (header_fields_set == false)
            throw DataNotReceivedYetException();
        
        return header_fields;
    }

    void streamContent(bool request_metadata) noexcept(false) {
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

            int response_code = get_response_status(header_fields);
            int metaint = get_metaint(header_fields);
            if (response_code != RESPONSE_CODE_OK)
                throw ResponseCodeNot200Exception();
            if (metaint < 0)
                throw ICYMetaIntInvalidValueException();


            std::string header_str = header_data_stringify(header_fields);
            fwrite(header_str.c_str(), 1, header_str.length(), stderr);

            if (metaint == 0)
                process_stream_content(sock, pollfd);
            else
                process_stream_content(sock, pollfd, metaint);

        } catch (ICYStramException &e) {
            close(sock);
            throw;
        }
    }
};