#include <iostream>
#include <cassert>
#include <signal.h>
#include "ArgsParser.h"
#include "ICYStream.h"

#define METADATA_YES "yes"
#define METADATA_NO "no"
#define REQUEST_METADATA "m"
#define STREAM_HOST "h"
#define STREAM_RESOURCE "r"
#define STREAM_PORT "p"
#define STREAM_TIMEOUT "t"
#define CLIENT_LOCAL_PORT "P"
#define CLIENT_MULTICAST_ADDR "B"
#define CLIENT_TIMEOUT "T"


sig_atomic_t stop_processing = false;

void sigint_hanler(int signal) {
    (void) signal; // silence unused variable warning
    stop_processing = true;
}

arguments_t validate_args(int argc, char *argv[]) noexcept(false) {
    ruleset_t args_rules {
        {STREAM_HOST, {true, ARG_DEFAULT_NOT_SET}},
        {STREAM_RESOURCE, {true, ARG_DEFAULT_NOT_SET}},
        {STREAM_PORT, {true, ARG_DEFAULT_NOT_SET}},
        {REQUEST_METADATA, {false, METADATA_NO}},
        {STREAM_TIMEOUT, {false, "5"}},
        {CLIENT_LOCAL_PORT, {false, ARG_DEFAULT_NOT_SET}}, // decides if we use part A or B
        {CLIENT_MULTICAST_ADDR, {false, ARG_DEFAULT_NOT_SET}},
        {CLIENT_TIMEOUT, {false, "5"}},
    };

    ArgsParser parser(args_rules);
    arguments_t args_map;
    /* remove first param (program name) */
    args_map = parser.parse_params(argc - 1, argv + 1);
    auto m_arg = args_map.at(REQUEST_METADATA);
    if (m_arg != METADATA_NO && m_arg != METADATA_YES)
        throw "invalid value '" + m_arg + "' of key '" + REQUEST_METADATA + "'";

    if (std::stoi(args_map.at(STREAM_TIMEOUT)) <= 0) // will throw if invalid
        throw "timeout must be positive integer";
    
    return args_map;
}

data_accesor write_mp3 = [](const char *data, int data_len) {
    fwrite(data, 1, data_len, stdout);
    return false;
};

data_accesor write_meta = [](const char *data, int data_len) {
    fwrite(data, 1, data_len, stderr);
    return false;
};

int main(int argc, char *argv[]) {

    arguments_t arg_map;
    try {
        arg_map = validate_args(argc, argv);
        std::string host = arg_map.at(STREAM_HOST);
        std::string port = arg_map.at(STREAM_PORT);
        std::string resource = arg_map.at(STREAM_RESOURCE);
        bool req_metadata = (arg_map.at(REQUEST_METADATA) == METADATA_YES ? true : false);
        int timeout = std::stoi(arg_map.at(STREAM_TIMEOUT));

        ICYStream stream(host, port, resource, timeout, stop_processing);
        if (arg_map.find(CLIENT_LOCAL_PORT) != arg_map.end()) { // we go with part B
            return 2;
        } else {
            stream.process_stream(req_metadata, write_mp3, write_meta);
        }
    } catch (const char *msg) { // catches argument validation errs
        std::cerr << msg << '\n';
        return 1;
    } catch (ICYStramException &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}