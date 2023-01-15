TARGET=beacon-flood
LDLIBS += -lpcap
CXX = g++
CXXFLAGS = -O0 -g -std=c++17

all: $(TARGET)

pch.o: pch.h pch.cpp

main.o: pch.h wlanhdr.h tools.h main.cpp

wlanhdr.o: pch.h wlanhdr.h wlanhdr.cpp

BeaconFlood.o: pch.h BeaconFlood.h BeaconFlood.cpp

gilgil_mac.o: gilgil_mac.h gilgil_mac.h

tools.o: pch.h tools.h tools.cpp

$(TARGET): gilgil_mac.o pch.o wlanhdr.o BeaconFlood.o tools.o main.o
	$(CXX) gilgil_mac.o pch.o wlanhdr.o wlanhdr.o BeaconFlood.o tools.o main.o -o $(TARGET) $(LOADLIBES) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o
