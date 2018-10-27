all : netfilter_block

netfilter_block: netfilter_block.o
	g++ -g -o netfilter_block netfilter_block.o -lnetfilter_queue

netfilter_block.o:
	g++ -g -c -o netfilter_block.o netfilter_block.cpp

clean:
	rm -f netfilter_block
	rm -f *.o

