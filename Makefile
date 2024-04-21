CXX=g++
CXXFLAGS=-std=c++20 -Wall -Werror -Wextra -pedantic
LDFLAGS=-lpcap

ifdef DEBUG
CXXFLAGS+=-g
endif

TARGET=ipk-sniffer

TEST_ARGS=-i eth0 -p 23 --tcp -n 2

SRC=$(wildcard src/*.cpp)

build: $(SRC)
	$(CXX) $(CXXFLAGS) -I./include $(SRC) -o $(TARGET) $(LDFLAGS)

run:
	@echo "\x1B[36m== Running $(TARGET) ==\x1B[0m"
	@$(TARGET) $(TEST_ARGS)

dev: build run

clean:
	@rm -rf $(TARGET) bin/*

test:
	@echo "\x1B[36m" && figlet -f slant "Tests" && echo "\x1B[0m"
	@python3 test/testikles.py

puml:
	@echo "Generating UML diagram"
	plantuml -tsvg docs/*.puml

zip:
	zip -r xhobza03.zip src/ include/ Makefile README.md CHANGELOG.md LICENSE

.PHONY: test
