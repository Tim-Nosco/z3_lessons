#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define swap tmp = table[i]; table[i] = table[j]; table[j] = tmp;


long int MAXKEYBYTE;
long int SAMPLEN;

uint16_t ** collect;

void single_run(){
	uint8_t key[32];

	uint8_t table[256];
	uint16_t i, j=0, c, tmp, k;
	for(i=0;i<32;i+=4){
		*((long int*)(key+i)) = lrand48();
	}
	for(i=0;i<256;i++){
		table[i] = i;
	}
	for(i=0;i<256;i++){
		j = (j + table[i] + key[i%32])&0xff;
		swap
	}
	i=0;j=0;
	for(c=0;c<MAXKEYBYTE;c++){
		i = (i+1)&0xff;
		j = (i+table[i])&0xff;
		swap
		k = table[ (table[i]+table[j])&0xff ] / 2;
		collect[c][k] += 1;
	}
}
int main(int argc, char const *argv[])
{
	if(argc<4) goto END;
	long int seed;
	sscanf(argv[1], "%ld", &seed);
	srand48(seed);
	sscanf(argv[2], "%ld", &MAXKEYBYTE);
	sscanf(argv[3], "%ld", &SAMPLEN);
	printf("%ld %ld %ld", seed, MAXKEYBYTE, SAMPLEN);
	uint32_t i, b;
	collect = calloc(MAXKEYBYTE, sizeof(uint16_t *));
	for(i=0;i<MAXKEYBYTE;i++){
		collect[i] = calloc(0x80, sizeof(uint16_t));
	}
	for(i=0;i<SAMPLEN;i++){
		single_run();
	}
	uint16_t m, c;
	for(i=0;i<MAXKEYBYTE;i++){
		printf("POSITION: %04x\n", i);
		m = 0;
		for(b=0;b<0x80;b++){
			c = collect[i][b];
			printf("%04x ", c);
			m = c>m ? c : m;
		}
		printf("\nmax: %04x\n", m);
	}
	END:
		return 0;
}