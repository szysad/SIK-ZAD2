#define CATCH_CONFIG_MAIN

#include "catch2.h"
#include "../ArgsParser.h"

TEST_CASE("ArgsParser tests", "[ArgsParser]")
{

    SECTION("normal behaviour no errors")
    {
        ruleset_t rules{
            {"a", {true, ARG_DEF_VAL_NOT_SET}},
            {"b", {true, ARG_DEF_VAL_NOT_SET}},
            {"c", {false, "C"}},
        };

        char *argv[] = {"-a", "A", "-b", "B", "-c", "C"};
        char *argv2[] = {"-c", "C", "-a", "A", "-b", "B"};
        char *argv3[] = {"-b", "B", "-a", "A"};

        arguments_t expected{
            {"a", "A"},
            {"b", "B"},
            {"c", "C"},
        };

        ArgsParser parser(rules);
        REQUIRE(parser.parse_params(6, argv) == expected);
        REQUIRE(parser.parse_params(6, argv2) == expected);
        REQUIRE(parser.parse_params(4, argv3) == expected);
    }

    SECTION("invalid args, exceptions expected")
    {
        ruleset_t rules{
            {"a", {true, ARG_DEF_VAL_NOT_SET}},
            {"b", {true, ARG_DEF_VAL_NOT_SET}},
            {"c", {false, "C"}},
        };

        char *argv1[] = {"a", "A", "-b", "B", "-c", "C"};
        char *argv2[] = {"-a", "A", "-b", "B", "-d", "D"};
        char *argv3[] = {"-c", "C", "-a", "A"};
        char *argv4[] = {"-a", "A", "-b", "B", "-c", "C", "-a", "AA"};
        char *argv5[] = {"-a", "A", "-b"};

        ArgsParser parser(rules);

        REQUIRE_THROWS(parser.parse_params(6, argv1));
        REQUIRE_THROWS(parser.parse_params(6, argv2));
        REQUIRE_THROWS(parser.parse_params(4, argv3));
        REQUIRE_THROWS(parser.parse_params(8, argv4));
        REQUIRE_THROWS(parser.parse_params(3, argv5));
    }

    SECTION("edge cases")
    {
        ruleset_t rules{};
        arguments_t args{};
        ArgsParser parser(rules);
        REQUIRE(parser.parse_params(0, {}) == args);

        char *argt[] = {"-a", "A"};
        REQUIRE_THROWS(parser.parse_params(2, argt));
    }

    SECTION("moodle examples section A")
    {
        ruleset_t rules{
            {"h", {true, ARG_DEF_VAL_NOT_SET}},
            {"r", {true, ARG_DEF_VAL_NOT_SET}},
            {"p", {true, ARG_DEF_VAL_NOT_SET}},
            {"m", {false, "no"}},
            {"t", {false, "5"}},
        };

        ArgsParser parser(rules);

        char *args1[] = {"waw02-03.ic.smcdn.pl", "/t050-1.mp3", "8000"};
        char *line1[] = {"-h", args1[0], "-r", args1[1], "-p", args1[2]};
        arguments_t arg1{
            {"h", args1[0]},
            {"r", args1[1]},
            {"p", args1[2]},
            {"m", "no"},
            {"t", "5"},
        };

        REQUIRE(parser.parse_params(6, line1) == arg1);

        char *args2[] = {"ant-waw-01.cdn.eurozet.pl", "8602", "/", "yes"};
        char *line2[] = {"-h", args2[0], "-p", args2[1], "-r", args2[2], "-m", args2[3]};
        arguments_t arg2{
            {"h", args2[0]},
            {"p", args2[1]},
            {"r", args2[2]},
            {"m", args2[3]},
            {"t", "5"},
        };

        REQUIRE(parser.parse_params(8, line2) == arg2);

        char *args3[] = {"8000", "waw02-03.ic.smcdn.pl", "/t043-1.mp3", "no"};
        char *line3[] = {"-p", args3[0], "-h", args3[1], "-r", args3[2], "-m", args3[3]};
        arguments_t arg3{
            {"p", args3[0]},
            {"h", args3[1]},
            {"r", args3[2]},
            {"m", args3[3]},
            {"t", "5"},
        };

        REQUIRE(parser.parse_params(8, line3) == arg3);
    }

    SECTION("moodle examples section B")
    {
        ruleset_t rules{
            {"h", {true, ARG_DEF_VAL_NOT_SET}},
            {"r", {true, ARG_DEF_VAL_NOT_SET}},
            {"p", {true, ARG_DEF_VAL_NOT_SET}},
            {"m", {false, "no"}},
            {"t", {false, "5"}},
            {"P", {true, ARG_DEF_VAL_NOT_SET}},
            {"B", {false, ARG_DEF_VAL_NOT_SET}},
            {"T", {false, "5"}},
        };

        ArgsParser p(rules);

        char *args1[] = {"waw02-03.ic.smcdn.pl", "/t050-1.mp3", "8000", "10000", "10"};
        char *line1[] = {"-h", args1[0], "-r", args1[1], "-p", args1[2], "-P", args1[3], "-t", args1[4]};
        arguments_t rez1 = {
            {"h", args1[0]},
            {"r", args1[1]},
            {"p", args1[2]},
            {"P", args1[3]},
            {"t", args1[4]},
            {"m", "no"},
            {"T", "5"},
        };

        arguments_t rez0 = p.parse_params(10, line1);
        REQUIRE(rez0 == rez1);

        char *args2[] = {"ant-waw-01.cdn.eurozet.pl", "8602", "/", "239.10.11.12", "54321"};
        char *line2[] = {"-h", args2[0], "-p", args2[1], "-r", args2[2], "-B", args2[3], "-P", args2[4]};
        arguments_t rez2{
            {"h", args2[0]},
            {"p", args2[1]},
            {"r", args2[2]},
            {"B", args2[3]},
            {"P", args2[4]},
            {"m", "no"},
            {"T", "5"},
            {"t", "5"},
        };

        REQUIRE(p.parse_params(10, line2) == rez2);
    }
}