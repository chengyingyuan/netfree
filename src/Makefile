C_FLAGS = -Wpedantic -Wall -g
LD_FLAGS =  -lssl -lcrypto -g

all: netfree netfree_udp

netfree: simpletun.o
	gcc -o $@ $^ $(LD_FLAGS) 

netfree_udp: simpletun_udp.o net_helpers.o
	gcc -o $@ $^ $(LD_FLAGS) 

%.o: %.c
	gcc $(C_FLAGS) -c $<

clean:
	-@rm -f simpletun simpletun_udp *.o
