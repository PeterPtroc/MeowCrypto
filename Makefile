CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wpedantic -Iinclude

BIN := meowcrypto
TEST_BIN := meowcrypto_tests

SRC := src/main.cpp src/meow_crypto.cpp
TEST_SRC := tests/test_meow.cpp src/meow_crypto.cpp

.PHONY: all clean test

all: $(BIN)

$(BIN): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC)

$(TEST_BIN): $(TEST_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_SRC)

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f $(BIN) $(TEST_BIN)
