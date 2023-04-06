CXXFLAGS=-std=c++11 -I../ -Wno-int-to-pointer-cast
CFLAGS=-std=c99 -I../
CC=gcc

all: standalone wrapper 

ifeq ("$(origin D)", "command line")
 CFLAGS += -DDEBUG
 CXXFLAGS += -DDEBUG
endif

ifeq ("$(origin G)", "command line")
 CFLAGS += -g
 CXXFLAGS += -g
endif

standalone:
	$(CXX) $(CXXFLAGS) -c ntfs_utils.cc
	$(CXX) $(CXXFLAGS) -c ntfs_fuzzer.cc
	$(CXX) $(CXXFLAGS) -c ntfs_standalone.cc
	$(CXX) $(CXXFLAGS) -o ntfs_standalone ntfs_utils.o ntfs_standalone.o ntfs_fuzzer.o

wrapper:
	$(CXX) -fPIC $(CXXFLAGS) -c ntfs_utils.cc
	$(CXX) -fPIC $(CXXFLAGS) -c ntfs_fuzzer.cc
	$(CXX) -fPIC $(CXXFLAGS) -c ntfs_wrapper.cc
	$(CXX) -fPIC -shared $(CXXFLAGS) -o ntfs_wrapper.so ntfs_utils.o ntfs_wrapper.o ntfs_fuzzer.o

clean:
	rm -f *.o
	rm -f *_standalone
	rm -f ntfs_wrapper.so
	rm -f meta.img out.img 
