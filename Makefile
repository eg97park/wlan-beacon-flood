TARGET=beacon-flood
LDLIBS += -lpcap
CXX = g++
CXXFLAGS = -O0 -g -std=c++17

all: $(TARGET)

tools.o: tools.h tools.cpp
	$(CXX) -c tools.cpp -o tools.o

main.o: main.cpp tools.h
	$(CXX) -c main.cpp

$(TARGET): tools.o main.o
	$(CXX) tools.o main.o -o $(TARGET) $(LOADLIBES) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o
