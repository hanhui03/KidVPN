# KidVPN Makefile for linux
# Author: hanhui (hanhui@acoinfo.com)

%.o: %.c
	gcc -DUSE_OPENSSL=1 -c $< -o $@

kidvpn: kv_cfg.o kv_lib.o kv_client.o kv_serv.o kv_main.o
	gcc -o kidvpn kv_cfg.o kv_lib.o kv_client.o kv_serv.o kv_main.o -lpthread -lcrypto

all: kidvpn

.PHONY: clean
clean:
	-rm -rf kidvpn *.o

# end
