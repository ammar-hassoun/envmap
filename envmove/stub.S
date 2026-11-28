/* Entry stub for a kernel started by kexec_load with our own boot parameters.
 * kexec hands over in 64-bit mode on identity-mapped pages with no usable GDT
 * and every register zero. The 64-bit boot protocol wants flat segments and
 * the boot parameters in %rsi. Two 64-bit slots are patched by the loader. */
	.text
	.code64
	.globl _start
_start:
	cli
	cld
	leaq	gdt(%rip), %rax
	movq	%rax, gdt_ptr+2(%rip)
	lgdt	gdt_ptr(%rip)
	movl	$0x18, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %fs
	movl	%eax, %gs
	leaq	stack_top(%rip), %rsp
	pushq	$0x10
	leaq	1f(%rip), %rax
	pushq	%rax
	lretq
1:
	movabsq	$0x1111111111111111, %rsi
	movabsq	$0x2222222222222222, %rax
	xorl	%ebx, %ebx
	xorl	%ebp, %ebp
	xorl	%edi, %edi
	jmpq	*%rax
	.balign 16
gdt:
	.quad 0
	.quad 0
	.quad 0x00af9a000000ffff
	.quad 0x00cf92000000ffff
gdt_ptr:
	.word 4*8-1
	.quad 0
	.balign 16
	.fill 512, 1, 0
stack_top:
