#include <iostream>
#include <cassert>
#include <signal.h>
#include "ArgsParser.h"
#include "ICYStream.h"

#define M_ARG_YES "yes"
#define M_ARG_NO "no"

sig_atomic_t stop_processing = false;

void sigint_hanler(int signal) {
    (void) signal; // silence unused variable warning
    stop_processing = true;
}

arguments_t validate_args(int argc, char *argv[]) noexcept(false) {
    ruleset_t args_rules {
        {"h", {true, ARG_DEFAULT_NOT_SET}},
        {"r", {true, ARG_DEFAULT_NOT_SET}},
        {"p", {true, ARG_DEFAULT_NOT_SET}},
        {"m", {false, M_ARG_NO}},
        {"t", {false, "5"}},
        {"P", {false, ARG_DEFAULT_NOT_SET}}, // decides if we use part A or B
        {"B", {false, ARG_DEFAULT_NOT_SET}},
        {"T", {false, "5"}},
    };

    ArgsParser parser(args_rules);
    arguments_t args_map;
    /* remove first param (program name) */
    args_map = parser.parse_params(argc - 1, argv + 1);
    auto m_arg = args_map.at("m");
    if (m_arg != M_ARG_NO && m_arg != M_ARG_YES)
        throw "invalid value '" + m_arg + "' of key 'm'";

    if (std::stoi(args_map.at("t")) <= 0) // will throw if invalid
        throw "timeout must be positive integer";
    
    return args_map;
}

data_accesor write_mp3 = [](const char *data, int data_len) {
    return fwrite(data, 1, data_len, stdout);
};

data_accesor write_meta = [](const char *data, int data_len) {
    return fwrite(data, 1, data_len, stderr);
};

int main(int argc, char *argv[]) {

    arguments_t arg_map;
    try {
        arg_map = validate_args(argc, argv);
        std::string host = arg_map.at("h");
        std::string port = arg_map.at("p");
        std::string resource = arg_map.at("r");
        bool req_metadata = (arg_map.at("m") == M_ARG_YES ? true : false);
        int timeout = std::stoi(arg_map.at("t"));

        ICYStream stream(host, port, resource, timeout, stop_processing);
        if (arg_map.find("P") != arg_map.end()) { // we go with part B
            throw "part B not implemented yet";
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