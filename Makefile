CXX=g++
CXXFLAGS=-std=c++2a -Wall -Wextra -Werror -pedantic

ifdef DEBUG
CXXFLAGS+=-g
endif

TARGET=bin/main

SRC=$(wildcard src/*.cpp)

build: $(SRC)
	$(CXX) $(CXXFLAGS) -I./include $(SRC) -o $(TARGET)

run:
	echo "\x1B[36m== Running $(TARGET) ==\x1B[0m"
	$(TARGET)

dev: build run