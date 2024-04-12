CXX=g++-13
CXXFLAGS=-std=c++20 -Wall -Wextra -pedantic -lpcap

ifdef DEBUG
CXXFLAGS+=-g
endif

# TODO: change to be root of project before release
TARGET=bin/ipk-sniffer

TEST_ARGS=-i eth0 -p 23 --tcp -n 2

MAC_FLAGS=-I/opt/homebrew/opt/libpcap/include -L/opt/homebrew/opt/libpcap/lib

SRC=$(wildcard src/*.cpp)

# TODO: Also source the headers from here /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/
build: $(SRC)
	$(CXX) $(CXXFLAGS) -I./include $(MAC_FLAGS) $(SRC) -o $(TARGET)

run:
	@echo "\x1B[36m== Running $(TARGET) ==\x1B[0m"
	@$(TARGET) $(TEST_ARGS)

dev: build run

clean:
	@rm -rf $(TARGET) bin/*

test:
	@echo "\x1B[36m" && figlet -f slant "Tests" && echo "\x1B[0m"
	@python3 test/testikles.py

.PHONY: test
