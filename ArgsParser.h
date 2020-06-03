#include <map>

#define ARG_DEFAULT_NOT_SET ""

/* <key, <is_mandatory, default value (if val = ARG_DEFAULT_NOT_SET no deafult value)>> */
typedef std::map<std::string, std::pair<bool, std::string>> ruleset_t;
/* <key, value> */
typedef std::map<std::string, std::string> arguments_t;

class ArgsParser {
    ruleset_t rules;

    public:
    /* <key, <is_mandatory, deafult value (if nullptr no deafult value)>> */
    ArgsParser(const ruleset_t &rules) : rules(rules) {}

    arguments_t parse_params(int argc, char *argv[]) noexcept(false) {
        arguments_t params;
        if (argc % 2 == 1)
            throw "not all values match their key";
        for (int i = 0; i < argc; i += 2) {
            if (argv[i][0] != '-')
                throw "key not starting with '-'";
            std::string key(argv[i] + 1); /* +1 to remove '-' from start */
            if (rules.find(key) == rules.end())
                throw "key not included in rules";
            auto ret = params.insert({key, std::string(argv[i + 1])});
            if (!ret.second)
                throw "same key given more then one";
        }

        /* check if all mandatory params are inserted and set deafult values if not set */
        /* ASSUMPTION: arg can't have deafult value and be mandatory */
        for (auto it = rules.begin(); it != rules.end(); it++) {
            if (it->second.first) {
                /* param is mandatory */
                if (params.find(it->first) == params.end())
                    throw "mandatory arg not given";
            } else {
                /* if arg not mandatory, has deafult value and is not set, set deafult value */
                if (params.find(it->first) == params.end() && it->second.second != ARG_DEFAULT_NOT_SET)
                    params.insert({it->first, it->second.second});
            }
        }
        return params;
    }
};