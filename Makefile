TARGET=beacon-flood
LDLIBS += -lpcap
CXX = g++
CXXFLAGS = -O0 -g -std=c++17

all: $(TARGET)

wlanhdr.o: wlanhdr.h wlanhdr.cpp
	$(CXX) -c wlanhdr.cpp -o wlanhdr.o

BeaconFlood.o: BeaconFlood.h BeaconFlood.cpp
	$(CXX) -c BeaconFlood.cpp -o BeaconFlood.o

tools.o: tools.h tools.cpp
	$(CXX) -c tools.cpp -o tools.o

main.o: main.cpp wlanhdr.h tools.h 
	$(CXX) -c main.cpp

$(TARGET): wlanhdr.o BeaconFlood.o tools.o main.o
	$(CXX) wlanhdr.o BeaconFlood.o tools.o main.o -o $(TARGET) $(LOADLIBES) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o
