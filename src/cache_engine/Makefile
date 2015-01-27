.SUFFIXES: .c .o .lo

CC = gcc
CFLAGS = -g -Wall
COMPILE = $(CC) $(CFLAGS)
INC_PATH = -I libngx/include/ -I libngx/include/os/unix/ -I ../utils/ -I ../cache_engine/
LIB_PATH = libpcap.a libngx/libngx.a libdns/dns.o libnet.a -lpthread -lcrypto

OBJECTS = main.o http_cap.o packet.o pkt_process.o loadconf.o reflect.o \
		  logger.o loadrsc.o parse_pkt.o libngx_init.o hostlist.o hostfilter.o \
		  dictionary.o http_sqs.o iniparser.o pid.o ref_time.o urlmatch.o

ALL_OBJS = $(OBJECTS)
ALL_PRGS = dnsReflector 
ALL_LIBS = 

vpath %.c ../utils
vpath %.h ../utils

all: $(ALL_OBJS) $(ALL_PRGS) $(ALL_LIBS)

dnsReflector:
	$(COMPILE) $(OBJECTS) $(LIB_PATH) -o $@ $<
.c:
	$(COMPILE) $(OBJECTS) $(LIB_PATH) $(INC_PATH) -o $@ $<
.c.o:
	$(COMPILE) $(INC_PATH) -c -o $@ $<
.c.lo:
	$(COMPILE) $(INC_PATH) -c -fPIC -o $@ $<
clean:
	rm -f $(ALL_OBJS) $(ALL_PRGS) $(ALL_LIBS)

