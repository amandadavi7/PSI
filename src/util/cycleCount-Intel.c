#include <stdio.h>
//return cycle counts as a 64-bit unsigned integer
unsigned long cycles(void) {
	unsigned int hi, lo;
	asm (
		"cpuid\n\t"/*serialize*/
		"rdtsc\n\t"/*read the clock*/
		"mov %%edx, %0\n\t"
		"mov %%eax, %1\n\t"
		: "=r" (hi), "=r" (lo):: "%rax", "%rbx", "%rcx", "%rdx"
	);
	return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}
