ALL = image_test create_corpus program_show program_test afl executor combined fsfuzz poc
CC = gcc
CFLAGS += -I../lkl/tools/lkl/include -Wall -g -O2 -Wextra \
	 -Wno-unused-parameter \
	 -Wno-missing-field-initializers -fno-strict-aliasing
CXX ?= g++
CXXFLAGS = -std=c++11 -g
CXXFLAGS += -fPIC -I../lkl/tools/lkl/include \
	 -Wall -g -O2 -Wextra \
	 -Wno-unused-parameter \
	 -Wno-missing-field-initializers -fno-strict-aliasing -pthread

# specific c++ flags for our fuzzers
CXXFLAGS_executor.o += -fpermissive
CXXFLAGS_combined.o += -fpermissive
CXXFLAGS_poc.o += -fpermissive

# specific link flags for our fuzzers
LDLIBS += -lrt -lpthread

all: $(ALL)

image_test: image_test.o Image.o Utils.o Constants.o
	$(CXX) $(CXXFLAGS) -o $@ $^

create_corpus: create_corpus.o Image.o Program.o Utils.o Constants.o SyscallMutator.o
	$(CXX) $(CXXFLAGS) -o $@ $^

program_show: program_show.o Image.o Program.o Utils.o Constants.o
	$(CXX) $(CXXFLAGS) -o $@ $^

program_test: program_test.o Image.o Program.o Utils.o Constants.o
	$(CXX) $(CXXFLAGS) -o $@ $^

afl:
	make -C afl-image
	make -C afl-image/llvm_mode
	make -C afl-syscall 
	make -C afl-image-syscall 

%.o: %.cpp
	#@echo "append $(CXXFLAGS_$@) for $@"
	$(CXX) $(CXXFLAGS) $(CXXFLAGS_$@) -fPIC -c -o $@ $<

# executor (CPP)
executor: executor.o Image.o Program.o Utils.o Constants.o ../lkl/tools/lkl/liblkl.a
	# order matters
	$(CXX) $^ $(LDLIBS) -o $@

# combined (CPP)
combined: combined.o Image.o Program.o Utils.o Constants.o ../lkl/tools/lkl/liblkl.a
	$(CXX) $^ $(LDLIBS) -o $@

# fsfuzz (C)
fsfuzz: fsfuzz.c ../lkl/tools/lkl/liblkl.a
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

# poc (CPP)
poc: poc.o Image.o Program.o Utils.o Constants.o ../lkl/tools/lkl/liblkl.a
	$(CXX) $(CXXFLAGS) -o $@ $^ -ldl -lrt -pthread

.PHONY: clean
clean:
	rm -rf *.o
	rm -rf $(ALL)
	make -C afl-image clean
	make -C afl-image/llvm_mode clean
	make -C afl-syscall clean
	make -C afl-image-syscall clean
