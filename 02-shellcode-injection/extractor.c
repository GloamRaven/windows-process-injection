#include <stdio.h>

extern unsigned char SHELL[];
extern unsigned char SHELL_END[];

int main(void)
{
	size_t len = (size_t)(SHELL_END - SHELL);

	printf("// %zu bytes\n", len);
	printf("unsigned char shellcode[] = {\n");
	for (size_t i = 0; i < len; i++) {
		printf("%s0x%02X%s",
			(i % 12 == 0) ? "    " : " ",
			SHELL[i],
			(i == len - 1) ? "\n" : ((i % 12 == 11) ? ",\n" : ","));
	}
	printf("};\n");
	return 0;
}
