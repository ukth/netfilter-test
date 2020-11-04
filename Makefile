all: netfilter-test

netfilter-test: main.cpp
	gcc -o netfilter-test main.cpp -lnetfilter_queue

clean:
	rm -f netfilter *.o
