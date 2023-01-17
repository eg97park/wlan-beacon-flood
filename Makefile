PROG=beacon-flood

CXX=g++
CXXFLAGS=-c -g -std=c++17 -O0
LDLIBS+=-lpcap

SRCS=$(wildcard *.cpp)
OBJS=$(SRCS:.cpp=.o)

PRECOMPILED_HEADER=pch.h
PCH_TARGET=$(PRECOMPILED_HEADER).gch
CXXFLAGS+=-include $(PRECOMPILED_HEADER)


all: $(PROG)

$(PCH_TARGET): $(PRECOMPILED_HEADER)
	$(CXX) $(CXXFLAGS) -MP -MMD -MT $(@:.gch=.d) -o $@ $<

$(PROG): $(OBJS)
	$(CXX) $(OBJS) -o $(PROG) $(LDLIBS)

%.o: %.cpp $(PCH_TARGET)
	$(CXX) $(CXXFLAGS) -MP -MMD -MT $(@:.o=.d) -o $@ $< 
	
clean:
	rm -f $(OBJS) $(PROG) $(PCH_TARGET) $(PCH_TARGET:.gch)

.PHONY: clean all