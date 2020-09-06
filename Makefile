
BIN=bin
SRC=src
EXT=${SRC}/externals

ifdef D
	DEBUG=-g
	OPT=
else
	DEBUG=
	OPT=-Ofast
endif

ifdef NH
	ARCH=
else
	ARCH=-msse4.2 -D__SSE4_2_
endif

ifdef P
	PROFILE=-pg -no-pie # for bug in gprof.
endif


# compiler settings
CC=g++ -std=c++11
CXX = gcc -std=gnu11
#COMPILER_OPTIONS=-O2
COMPILER_OPTIONS=-g3 -O2 -march=native -funroll-loops -mrdrnd -fpermissive #-fPIC -mavx -maes -mpclmul -DRDTSC -DTEST=AES128
CXXFLAGS = -Wall $(DEBUG) $(PROFILE) $(OPT) $(ARCH) -m64 -I. -I./src/util/counting_quotient_filter -Wno-unused-result -Wno-unused-function -Wno-strict-aliasing
# Inserir o -mrdrnd para compilar no meu pc

DEBUG_OPTIONS=-g3 -ggdb #-Wall -Wextra 

BATCH=

ARCHITECTURE = $(shell uname -m)
ifeq (${ARCHITECTURE},x86_64)
MIRACL_MAKE:=linux64
GNU_LIB_PATH:=x86_64
else
MIRACL_MAKE:=linux
GNU_LIB_PATH:=i386
endif

INCLUDE=-I..  `pkg-config --cflags glib-2.0`

LIBRARIES=-lgmp -lgmpxx -lpthread  -L /usr/lib  -lssl -lcrypto `pkg-config --libs glib-2.0` 
CFLAGS=

# all source files and corresponding object files 
SOURCES_CORE := $(shell find ${CORE} -type f -name '*.cpp' -not -path '*/Miracl/*' -a -not -path '*/mains/*')
OBJECTS_CORE := $(SOURCES_CORE:.cpp=.o)
# directory for PSI related sources
SOURCES_UTIL=${SRC}/util/*.cpp
OBJECTS_UTIL=${SRC}/util/*.o
SOURCES_OT=${SRC}/util/ot/*.cpp
OBJECTS_OT=${SRC}/util/ot/*.o
SOURCES_CRYPTO=${SRC}/util/crypto/*.cpp
OBJECTS_CRYPTO=${SRC}/util/crypto/*.o
SOURCES_HASHING=${SRC}/hashing/*.cpp
OBJECTS_HASHING=${SRC}/hashing/*.o
SOURCES_FILTER=${SRC}/util/cuckoo_filter/*.cc
OBJECTS_FILTER=${SRC}/util/cuckoo_filter/*.o
SOURCES_COUNTING_QUOTIENT_FILTER=$(wildcard ${SRC}/util/counting_quotient_filter/*.c)
OBJECTS_COUNTING_QUOTIENT_FILTER=$(patsubst %.c,%.o, $(wildcard ${SRC}/util/counting_quotient_filter/*.c))
# naive hashing-based solution
SOURCES_NAIVE=${SRC}/naive-hashing/*.cpp
OBJECTS_NAIVE=${SRC}/naive-hashing/*.o
# public-key-based PSI
SOURCES_DHPSI=${SRC}/pk-based/*.cpp
OBJECTS_DHPSI=${SRC}/pk-based/*.o
# public-key-based PSI (gattaca)
SOURCES_DHPSI_GATTACA=${SRC}/pk-based_gattaca/*.cpp
OBJECTS_DHPSI_GATTACA=${SRC}/pk-based_gattaca/*.o
# public-key-based PSI (optimized)
SOURCES_DHPSI_OPTIMIZED=${SRC}/pk-based_optimized/*.cpp
OBJECTS_DHPSI_OPTIMIZED=${SRC}/pk-based_optimized/*.o
# generate-filter
SOURCES_DH_GENERATE_FILTER=${SRC}/generate_filter/*.cpp
OBJECTS_DH_GENERATE_FILTER=${SRC}/generate_filter/*.o
# generate-couting-quotient-filter
SOURCES_DH_GENERATE_COUNTING_QUOTIENT_FILTER=${SRC}/generate_counting_quotient_filter/*.cpp
OBJECTS_DH_GENERATE_COUNTING_QUOTIENT_FILTER=${SRC}/generate_counting_quotient_filter/*.o
# third-party-based PSI
SOURCES_SERVERAIDED=${SRC}/server-aided/*.cpp
OBJECTS_SERVERAIDED=${SRC}/server-aided/*.o
# OT-based PSI
SOURCES_OTPSI=${SRC}/ot-based/*.cpp
OBJECTS_OTPSI=${SRC}/ot-based/*.o
#OBJECTS_BENCH=${SRC}/bench_psi.cpp
# directory for the Miracl submodule and library
MIRACL_LIB_DIR=${EXT}/miracl_lib
SOURCES_MIRACL=${EXT}/Miracl/*
OBJECTS_MIRACL=${MIRACL_LIB_DIR}/*.o
MIRACL_LIB=${EXT}/miracl_lib/miracl.a

all: miracl fltr core bench demo
	@echo "make all done."

core: ${OBJECTS_CORE}

fltr: ${OBJECTS_COUNTING_QUOTIENT_FILTER}

src/util/counting_quotient_filter/%.o: src/util/counting_quotient_filter/%.c
	$(CXX) $(CXXFLAGS) $< -c -o $@

%.o:%.cpp %.h
	${CC} $< ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} -c ${INCLUDE} ${LIBRARIES} ${CFLAGS} ${BATCH} -o $@

bench:  
	${CC} -o psi.exe ${SRC}/mains/bench_psi.cpp ${OBJECTS_DHPSI_GATTACA} ${OBJECTS_DHPSI_OPTIMIZED} ${OBJECTS_DH_GENERATE_FILTER} ${OBJECTS_DH_GENERATE_COUNTING_QUOTIENT_FILTER} ${OBJECTS_DHPSI} ${OBJECTS_OTPSI} ${OBJECTS_NAIVE} ${OBJECTS_SERVERAIDED} ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_FILTER} ${OBJECTS_COUNTING_QUOTIENT_FILTER} ${OBJECTS_MIRACL} ${CFLAGS} ${DEBUG_OPTIONS} ${LIBRARIES} ${MIRACL_LIB} ${INCLUDE} ${COMPILER_OPTIONS}

demo:  
	${CC} -o demo.exe ${SRC}/mains/psi_demo.cpp ${OBJECTS_DHPSI_GATTACA} ${OBJECTS_DHPSI_OPTIMIZED} ${OBJECTS_DH_GENERATE_FILTER} ${OBJECTS_DH_GENERATE_COUNTING_QUOTIENT_FILTER} ${OBJECTS_DHPSI} ${OBJECTS_OTPSI} ${OBJECTS_NAIVE} ${OBJECTS_SERVERAIDED} ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_FILTER} ${OBJECTS_COUNTING_QUOTIENT_FILTER} ${OBJECTS_MIRACL} ${CFLAGS} ${DEBUG_OPTIONS} ${LIBRARIES} ${MIRACL_LIB} ${INCLUDE} ${COMPILER_OPTIONS}

test: core
	${CC} -o test.exe ${SRC}/mains/test_psi.cpp ${OBJECTS_DHPSI_GATTACA} ${OBJECTS_DHPSI_OPTIMIZED} ${OBJECTS_DH_GENERATE_FILTER} ${OBJECTS_DH_GENERATE_COUNTING_QUOTIENT_FILTER} ${OBJECTS_DHPSI} ${OBJECTS_OTPSI} ${OBJECTS_NAIVE} ${OBJECTS_SERVERAIDED} ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_FILTER} ${OBJECTS_COUNTING_QUOTIENT_FILTER} ${OBJECTS_MIRACL} ${CFLAGS} ${DEBUG_OPTIONS} ${LIBRARIES} ${MIRACL_LIB} ${INCLUDE} ${COMPILER_OPTIONS}
	./test.exe -r 0 -t 10 & 
	./test.exe -r 1 -t 10

cuckoo:  
	${CC} -o cuckoo.exe ${SRC}/mains/cuckoo_analysis.cpp ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO} ${OBJECTS_MIRACL} ${CFLAGS} ${DEBUG_OPTIONS} ${LIBRARIES} ${MIRACL_LIB} ${INCLUDE} ${COMPILER_OPTIONS}


# this will create a copy of the files in ${SOURCES_MIRACL} and its sub-directories and put them into ${MIRACL_LIB_DIR} without sub-directories, then compile it
miracl:	${MIRACL_LIB_DIR}/miracl.a

# copy Miracl files to a new directory (${CORE}/util/miracl_lib/), call the build script and delete everything except the archive, header and object files.
${MIRACL_LIB_DIR}/miracl.a: ${SOURCES_MIRACL}
	@cp ${MIRACL_MAKE} ${EXT}/Miracl/lib
	@find ${EXT}/Miracl/ -type f -exec cp '{}' ${EXT}/miracl_lib \;
	@cd ${EXT}/miracl_lib/; bash ${MIRACL_MAKE}; find . -type f -not -name '*.a' -not -name '*.h' -not -name '*.o' -not -name '.git*'| xargs rm

# only clean example objects, test object and binaries
clean:
	rm -f ${OBJECTS_EXAMPLE} ${OBJECTS_TEST} *.exe ${OBJECTS_DHPSI_GATTACA} ${OBJECTS_DHPSI_OPTIMIZED} ${OBJECTS_DH_GENERATE_FILTER} ${OBJECTS_DH_GENERATE_COUNTING_QUOTIENT_FILTER} ${OBJECTS_DHPSI} ${OBJECTS_OTPSI} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO} ${OBJECTS_NAIVE} ${OBJECTS_SERVERAIDED} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_FILTER} ${OBJECTS_COUNTING_QUOTIENT_FILTER}

# this will clean everything: example objects, test object and binaries and the Miracl library
cleanall: clean
	rm -f ${OBJECTS_MIRACL} ${MIRACL_LIB_DIR}/*.a
