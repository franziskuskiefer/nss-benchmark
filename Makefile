
# Set NSS_PATH in your environment if it's not installed.

NSS_INCLUDES=-I/usr/include/nspr
NSS_LIBS=-lnss3

CXX=g++
DEBUG_ARGS=-g
OPT_ARGS=-O2

FILES=nss-bench.cc aead.cc hash.cc

all:
	$(CXX) $(DEBUG_ARGS) $(OPT_ARGS) $(NSS_INCLUDES) $(NSS_LIBS) $(FILES) lib/*.cc -o nss-bench

clean:
	rm -rf nss-bench
