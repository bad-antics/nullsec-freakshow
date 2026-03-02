CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pthread
TARGET   = golem
SRC      = golem.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)

.PHONY: all clean install
