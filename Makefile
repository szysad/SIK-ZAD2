CPPFLAGS= -Wall -Wextra -O2

main: radio-proxy

clean:
	rm -f radio-proxy *.o

radio-proxy: radio-proxy.cpp ArgsParser.h ICYStream.h UDPMiddleman.h
	g++ $(CPPFLAGS) radio-proxy.cpp ArgsParser.h ICYStream.h UDPMiddleman.h -o radio-proxy