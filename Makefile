all:
	gcc -o nat nat.c checksum.c checksum.h -lnfnetlink -lnetfilter_queue

clean:
	@rm -f nat
