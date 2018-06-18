#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define swap tmp = table[i]; table[i] = table[j]; table[j] = tmp;

uint16_t * collect;

void single_run(){
	uint8_t key[32];
	*((long int*)(key+0x0)) = lrand48();
	*((long int*)(key+0x4)) = lrand48();
	*((long int*)(key+0x8)) = lrand48();
	*((long int*)(key+0xc)) = lrand48();
	uint8_t table[256];
	uint16_t i, j=0, c, tmp, k;
	for(i=0;i<256;i++){
		table[i] = i;
	}
	for(i=0;i<256;i++){
		j = (j + table[i] + key[i%32])&0xff;
		swap
	}
	for(i=0,j=0,c=0;c<1024;c++){
		i = (i+1)&0xff;
		j = (i+table[i])&0xff;
		swap
		k = table[ (table[i]+table[j])&0xff ] / 2;
		collect[c*0x7f+k] += 1;
	}
}
#define SAMPLEN 100000
int main(int argc, char const *argv[])
{
	if(argc<2) goto END;
	long int seed;
	sscanf(argv[1], "%l", seed);
	srand48(seed);
	collect = calloc(1024, 2*0x7f);
	uint32_t i, b;
	for(i=0;i<SAMPLEN;i++){
		single_run();
	}
	uint16_t m, c;
	for(i=0;i<1024;i++){
		printf("POSITION: %04x\n", i);
		m = 0;
		for(b=0;b<0x7f;b++){
			c = collect[i*0x7f+b];
			printf("%04x ", c);
			m = c>m ? c : m;
		}
		printf("\nmax: %04x\n", m);
	}
	END:
		return 0;
}