Fuzzing the Latest NTFS in Linux with Papora:An Empirical Study
===========================================

### Tested Environment
- OS: Ubuntu 20.04 LTS
- clang 6.0.0
- gcc 9.4.0
- libboost1.71-dev

### Preparation
- Clone the project
    - git clone --recursive https://github.com/ambergroup-labs/papora.git
    - or if you've cloned it already
        - git submodule update --init
- Compile fuzzer
    - use compile python script, it will build the fuzzers and lkl
        - ./compile -t ntfs3 -c
	    - Usage: -t: file system type -c: clean build, use it only when you need a total rebuild
    - there are 4 target applications generated
        - ./fuzzers/ntfs3-fsfuzz          for fuzzing images only
        - ./fuzzers/ntfs3-executor        for fuzzing file operations only
        - ./fuzzers/ntfs3-combined        for fuzzing both (Papora)
        - ./fuzzers/ntfs3-poc             for testcase reproduce

- Compile image parser 
    - cd fs/ntfs3
    - make
    - two output generated
        - ntfs3_wrapper.so: AFL linked with this .so to compress and decompress an image
        - ntfs3_standalone: this is used to release image offline given a compressed image and the original seed image. If you use *online* mode, you can release a batch of compressed images in an efficient way for reproducing.
    - Check fs/[fs name]/README.md for how to build in detail!

- Seed images
    - Prepare a ntfs image
    - Let's assume we use images/ntfs.img here
        - Build the istat file for generating starting program 
            - cd istat
            - ./istat -i ../images/ntfs.img -t ntfs3 -o ntfs.istat
                - Usage: -i: seed image -t: file system type -o: output
            - Then we get the initial image status file: istat/ntfs.istat

- Run fuzzer
    - We need a directory to store seed programs based on the initial image status
        - mkdir prog
    - Create seed programs
        - ./core/create_corpus istat/ntfs.istat prog
            - Usage: create_corpus [istat file] [output dir]
        - To show readable C code of a serialized program
            - ./core/program_show prog/open_read0
    - Create the input directory and the output directory for Papora
        - mkdir input
        - mkdir output
        - ./core/afl-image-syscall/afl-fuzz -b ntfs3 -s fs/ntfs3/ntfs_wrapper.so -e images/ntfs.img -S ntfs3 -y prog -i input -o output -m none -u 2 -g images/mutate.img -- ./fuzzers/ntfs3-combined -t ntfs3 -p @@ -v -i images/mutate.img
            - -b: shared memory name for storing image (which should be distinct)
            - -s: fs (de)compressor
            - -e: seed image
            - -S: AFL argument (slave name) (which should be distinct, optional)
                - No -M support
            - -y: the seed program directory
            - -i: AFL argument (input directory) (which should be distinct)
            - -o: AFL argument (output directory)
            - -u: #CPU
            - -g: generated mutated image
        - How to reproduce a generated testcase (compressed image + serialized program)
            - ./fuzzers/ntfs3-poc -t ntfs3 -s fs/ntfs3/ntfs_wrapper.so -i images/ntfs.img -g poc.img -p output/ntfs3/crashes/id:000000,sig:11,src:000000,op:havoc,rep:8
                - Usage: -i: seed image -t: file system type -g: generated mutated image -p the testcase
            - it will generate poc.img: the mutated image to be mounted
            - poc.case: the serialized program 
            - You can use poc.img and poc.case to reproduce the bug in the upstream linux kernel

### Contacts
- Chiachih Wu (chiachih.wu@ambergroup.io)
