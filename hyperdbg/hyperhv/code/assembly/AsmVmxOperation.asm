PUBLIC AsmEnableVmxOperation
PUBLIC AsmVmxVmcall
PUBLIC AsmHypervVmcall
PUBLIC AsmVmfunc

.code _text

;------------------------------------------------------------------------

AsmEnableVmxOperation PROC PUBLIC

    xor rax,rax			; Clear the RAX
    mov rax,cr4
    or rax,02000h		; Set the 14th bit
    mov cr4,rax
    ret

AsmEnableVmxOperation ENDP

;------------------------------------------------------------------------

; [DOWNSTREAM] A thread can be suspended on any instruction of this routine
; (NtGetContextThread then unwinds its kernel stack). Without unwind data the
; frame is unwound as a leaf, and every boundary after the first push takes
; RFLAGS or a saved register as the return address, so the call fails with
; STATUS_UNSUCCESSFUL. The frame is described below. RFLAGS is saved last and
; restored by a helper, so that the epilog is lea/pop/ret, which the unwinder
; recognizes (popfq inside an epilog is not), and lea leaves the flags alone.

AsmVmxVmcall PROC FRAME

    push    r10
    .pushreg r10
    push    r11
    .pushreg r11
    push    r12
    .pushreg r12
    pushfq
    .allocstack 8
    .endprolog
    mov     r10, 48564653H          ; [HVFS]
    mov     r11, 564d43414c4cH      ; [VMCALL]
    mov     r12, 4e4f485950455256H  ; [NOHYPERV]
    vmcall                          ; VmxVmcallHandler(UINT64 VmcallNumber, UINT64 OptionalParam1, UINT64 OptionalParam2, UINT64 OptionalParam3)
    call    AsmVmxVmcallRestoreFlags
    lea     rsp, [rsp+8]
    pop     r12
    pop     r11
    pop     r10
    ret                             ; Return type is NTSTATUS and it's on RAX from the previous function, no need to change anything

AsmVmxVmcall ENDP

; Loads the RFLAGS that AsmVmxVmcall saved just above this helper's return address.
AsmVmxVmcallRestoreFlags PROC FRAME

    push    qword ptr [rsp+8]
    .allocstack 8
    .endprolog
    popfq
    ret

AsmVmxVmcallRestoreFlags ENDP

;------------------------------------------------------------------------

AsmHypervVmcall PROC

    pushfq

    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
    push rbp	; rsp
    push rbx
    push rdx
    push rcx
    push rax

    mov rax, qword ptr [rcx+0h]
    mov rdx, qword ptr [rcx+10h]
    mov rbx, qword ptr [rcx+18h]
    ; mov rsp, qword ptr [rcx+20h]
    mov rbp, qword ptr [rcx+28h]
    mov rsi, qword ptr [rcx+30h]
    mov rdi, qword ptr [rcx+38h]
    mov r8, qword ptr [rcx+40h]
    mov r9, qword ptr [rcx+48h]
    mov r10, qword ptr [rcx+50h]
    mov r11, qword ptr [rcx+58h]
    mov r12, qword ptr [rcx+60h]
    mov r13, qword ptr [rcx+68h]
    mov r14, qword ptr [rcx+70h]
    mov r15, qword ptr [rcx+78h]

    push rcx
    mov rcx, qword ptr [rcx+08h]

    vmcall                          ; __fastcall Vmcall(rcx = HypercallInputValue, rdx = InputParamGPA, r8 = OutputParamGPA)

    pop rcx

    mov qword ptr [rcx+0h], rax
    mov qword ptr [rcx+10h], rdx
    mov qword ptr [rcx+18h], rbx
    ; mov qword ptr [rcx+20h], rsp
    mov qword ptr [rcx+28h], rbp
    mov qword ptr [rcx+30h], rsi
    mov qword ptr [rcx+38h], rdi
    mov qword ptr [rcx+40h], r8
    mov qword ptr [rcx+48h], r9
    mov qword ptr [rcx+50h], r10
    mov qword ptr [rcx+58h], r11
    mov qword ptr [rcx+60h], r12
    mov qword ptr [rcx+68h], r13
    mov qword ptr [rcx+70h], r14
    mov qword ptr [rcx+78h], r15

    mov qword ptr [rcx+08h], rcx

    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    popfq

    ret

AsmHypervVmcall ENDP

;------------------------------------------------------------------------

;
; It's unsafe to call this function directly, make sure the CPU supports it
;
; The following function assumes that,
;	                                    ECX: EptpIndex
;	                                    EDX: Function

AsmVmfunc PROC

	mov	eax, edx
	db	0fh, 01h, 0d4h ; equals to VMFUNC
	setna 	al

	ret

AsmVmfunc ENDP

;------------------------------------------------------------------------

END