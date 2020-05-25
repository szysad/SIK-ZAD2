#include <iostream>
#include <cassert>
#include <exception>
#include "ArgsParser.h"

#define M_ARG_YES "yes"
#define M_ARG_NO "no"

arguments_t validate_args(int argc, char *argv[]) {
    ruleset_t args_rules {
        {"h", {true, ARG_DEFAULT_NOT_SET}},
        {"r", {true, ARG_DEFAULT_NOT_SET}},
        {"p", {true, ARG_DEFAULT_NOT_SET}},
        {"m", {false, M_ARG_NO}},
        {"t", {false, "5"}},
    };

    ArgsParser parser(args_rules);
    arguments_t args_map;
    /* remove first param (program name) */
    args_map = parser.parse_params(argc - 1, argv + 1);
    auto m_arg = args_map.at("m");
    if (m_arg != M_ARG_NO && m_arg != M_ARG_YES)
        throw std::runtime_error("invalid value '" + m_arg + "' of key 'm'");
    
    return args_map;
}

int main(int argc, char *argv[]) {

    arguments_t arg_map;
    try {
        arg_map = validate_args(argc, argv);
    } catch (std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }

    return 0;
}