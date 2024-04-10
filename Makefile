CXX=g++
CXXFLAGS=-std=c++2a -Wall -Wextra -Werror -pedantic

ifdef DEBUG
CXXFLAGS+=-g
endif

# TODO: change to be root of project before release
TARGET=bin/ipk-sniffer

SRC=$(wildcard src/*.cpp)

build: $(SRC)
	$(CXX) $(CXXFLAGS) -I./include $(SRC) -o $(TARGET)

run:
	@echo "\x1B[36m== Running $(TARGET) ==\x1B[0m"
	@$(TARGET)

dev: build run