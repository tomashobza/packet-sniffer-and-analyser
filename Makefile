CXX=g++
CXXFLAGS=-std=c++2a -Wall -Wextra -Werror -pedantic

ifdef DEBUG
CXXFLAGS+=-g
endif

# TODO: change to be root of project before release
TARGET=bin/ipk-sniffer

TEST_ARGS=-i eth0 -p 23 --tcp -n 2

SRC=$(wildcard src/*.cpp)

build: $(SRC)
	$(CXX) $(CXXFLAGS) -I./include $(SRC) -o $(TARGET)

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
