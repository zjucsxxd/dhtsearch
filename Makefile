CC = gcc
CPP = g++
CFLAGS = -g -Wall -Wno-deprecated -Wno-c++11-extensions
MKDEP=/usr/X11R6/bin/makedepend -Y
OS := $(shell uname)
ifeq ($(OS), Darwin)
  LIBS = 
  GLIBS = -framework OpenGL -framework GLUT
else
  LIBS = -lcrypto
  GLIBS = -lGL -lGLU -lglut
endif

BINS = dhtn dhtc
HDRS = netimg.h hash.h ltga.h imgdb.h
SRCS = ltga.cpp 
HDRS_SLN = dhtn.h
SRCS_SLN = dhtn.cpp hash.cpp imgdb.cpp 
OBJS = $(SRCS_SLN:.cpp=.o) $(SRCS:.cpp=.o)

all: $(BINS)

dhtn: $(OBJS) $(HDRS)
	$(CPP) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

dhtc: dhtc.o netimg.h netimg.o
	$(CPP) $(CFLAGS) -o $@ $< netimg.o $(GLIBS)

%.o: %.cpp
	$(CPP) $(CFLAGS) $(INCLUDES) -c $<

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

.PHONY: clean
clean: 
	-rm -f -r $(OBJS) *.o *~ *core* $(BINS)

depend: $(SRCS) $(SRCS_SLN) $(HDRS) $(HDRS_SLN) Makefile
	$(MKDEP) $(CFLAGS) $(SRCS) $(SRCS_SLN) $(HDRS) $(HDRS_SLN) >& /dev/null

altdepend: $(ALTSRCS_SLN) $(ALTHDRS) $(HDRS_SLN) Makefile
	$(MKDEP) $(CFLAGS) $(ALTSRCS_SLN) $(ALTHDRS) $(HDRS_SLN) >& /dev/null

# DO NOT DELETE

ltga.o: ltga.h
dhtn.o: netimg.h hash.h imgdb.h ltga.h dhtn.h
hash.o: netimg.h hash.h
imgdb.o: ltga.h netimg.h hash.h imgdb.h
imgdb.o: ltga.h hash.h netimg.h
dhtn.o: hash.h imgdb.h ltga.h netimg.h
