all:
	gcc -o nat nat.c -lnfnetlink -lnetfilter_queue

clean:
	@rm -f nat
