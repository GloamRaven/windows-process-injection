PUBLIC SHELL
PUBLIC SHELL_END

.code

SHELL PROC
jmp start

get_func_addr:
	; in:	rbx = module base
	;		rsi = AddressOfNames (absolute)
	;		rcx = AddressOfNameOrdinals (absolute)
	;		rdx = 0
	;		rdi = target hash
	;		[rbp+18h] = export directory (absolute)
	; out:	rax = function address, or 0 when not found
loop_ent:
	mov r10, [rbp + 18h]
	cmp edx, dword ptr [r10 + 18h]	; rdx >= NumberOfNames ?
	jae not_found
	inc rdx
	mov eax, dword ptr [rsi]		; name RVA
	add rsi, 4

	push rax						; 해시 계산이 망치는 것만 저장
	push rbx
	push rsi
	push rdi

	add rbx, rax					; rbx = base + name RVA
	mov rsi, rbx
	xor rax, rax
	xor rdi, rdi
hash:
	mov al, byte ptr [rsi]
	add rsi, 1
	add rdi, rax
	test al, al
	jnz hash
	mov qword ptr [rbp + 10h], rdi	; 계산된 해시를 스크래치에 보관

	pop rdi							; rdi = 목표 해시로 복원
	pop rsi
	pop rbx
	pop rax

	cmp [rbp + 10h], rdi
	jne loop_ent

	;찾음. 이름 인덱스는 rdx-1
	movzx rdx, word ptr [rcx + rdx * 2 - 2]	; ordinal
	mov rdi, [rbp + 18h]
	xor rsi, rsi
	mov esi, dword ptr [rdi + 1ch]			; AddressOfFunctions RVA
	mov rdi, rbx
	add rsi, rdi							; -> absolute
	xor rbx, rbx
	mov ebx, dword ptr [rsi + rdx * 4]		; function RVA
	add rdi, rbx
	mov rax, rdi
	ret

not_found:
	xor rax, rax
	ret

start:
	push rbp
	push rbx
	push rsi
	push rdi
	mov rax, rsp							; 원래 rsp 보관
	sub rsp, 70h							; 스크래치 블록
	and rsp, 0FFFFFFFFFFFFFFF0h				; 16바이트 정렬
	mov rbp, rsp							; rbp = 스크래치 베이스
	sub rsp, 40h							; 쉐도우 스페이스, 이후 모든 call이 공유
	mov [rbp+8], rax						; 원래 rsp 저장

	xor rax, rax
	xor rdi, rdi
	xor rsi, rsi
	xor rcx, rcx
	mov rax, gs : [rax+60h] ; peb
	mov rax, [rax + 18h] ; peb_ldr_data
	mov rax, [rax + 10h] ; .exe inloadordermodulelist
	mov rbx, [rax] ; ntdll.dll inloadordermodulelist
	mov rbx, [rbx] ; kernel32.dll inloadordermodulelist
	mov rbx, [rbx + 30h] ; kernel32.dll base adr

	mov edi, dword ptr [rbx + 3ch] ; pe header
	add rdi, rbx
	xor r8, r8
	add r8, rdi
	add r8, 40h
	mov edi, dword ptr [r8 + 48h]	; Export Table
	add rdi, rbx
	mov [rbp + 18h], rdi
	mov esi, dword ptr [rdi + 20h]	; Export name Table
	add rsi, rbx
	mov ecx, dword ptr [rdi + 24h]	; Ordinal Table
	add rcx, rbx
	xor rdx, rdx

	xor rdi, rdi
	add di, 496h
	call get_func_addr				; get loadlibrary address
	test rax, rax
	jz error
	mov [rbp + 48h], rax			; loadlibrary address

	xor rax, rax
	mov qword ptr[rbp+20h], rax
	mov qword ptr[rbp+28h], rax
	mov byte ptr[rbp+20h], 75h	; u
	mov byte ptr[rbp+21h], 73h	; s
	mov byte ptr[rbp+22h], 65h	; e
	mov byte ptr[rbp+23h], 72h	; r
	mov byte ptr[rbp+24h], 33h	; 3
	mov byte ptr[rbp+25h], 32h	; 2
	mov byte ptr[rbp+26h], 2eh	; .
	mov byte ptr[rbp+27h], 64h	; d
	mov byte ptr[rbp+28h], 6ch	; l
	mov byte ptr[rbp+29h], 6ch	; l
	lea rcx, [rbp+20h]
	call qword ptr[rbp + 48h]	; call loadlibrary
	test rax, rax
	jz error

	; user32.dll의 EAT, ENT, Ordinal Table 주소 구하기
	xor rdi, rdi
	xor rsi, rsi
	xor rcx, rcx
	mov rbx, rax	; rax는 user32.dll base adr
	mov edi, dword ptr [rbx + 3ch]
	add rdi, rbx
	xor r8, r8
	add r8, rdi
	add r8, 40h
	mov edi, dword ptr [r8 + 48h]
	add rdi, rbx
	mov [rbp + 18h], rdi
	mov esi, dword ptr [rdi + 20h]
	add rsi, rbx
	mov ecx, dword ptr [rdi + 24h]
	add rcx, rbx
	xor rdx, rdx
	xor rdi, rdi
	add di, 42fh
	call get_func_addr	; MessageBoxA address
	test rax, rax
	jz error
	mov [rbp + 50h], rax

	xor rax, rax
	xor rcx, rcx
	xor rdx, rdx
	mov qword ptr[rbp+28h], rax
	mov byte ptr[rbp+28h], 43h
	mov byte ptr[rbp+29h], 61h
	mov byte ptr[rbp+2ah], 77h
	mov byte ptr[rbp+2bh], 21h
	mov byte ptr[rbp+2ch], 20h
	mov byte ptr[rbp+2dh], 43h
	mov byte ptr[rbp+2eh], 61h
	mov byte ptr[rbp+2fh], 77h
	xor r8, r8
	mov qword ptr[rbp+30h], rcx
	mov byte ptr[rbp+30h], 21h
	mov byte ptr[rbp+32h], 47h
	mov byte ptr[rbp+33h], 6ch
	mov byte ptr[rbp+34h], 6fh
	mov byte ptr[rbp+35h], 61h
	mov byte ptr[rbp+36h], 6dh
	mov byte ptr[rbp+37h], 52h
	mov byte ptr[rbp+38h], 61h
	mov byte ptr[rbp+39h], 76h
	mov byte ptr[rbp+3ah], 65h
	mov byte ptr[rbp+3bh], 6eh
	mov byte ptr[rbp+3ch], 0h
	xor r9, r9
	lea rdx, [rbp+28h]
	lea r8, [rbp+32h]
	call qword ptr[rbp+50h]	; call messageBoxA(0, 'Caw! Caw!', 'GloamRaven', 0)
	jmp code_end

error:
	xor rax, rax
code_end:
	mov rsp, [rbp+8]
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

SHELL ENDP
SHELL_END LABEL BYTE
End