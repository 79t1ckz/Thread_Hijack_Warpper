
public hijack_warpper_routine

.code

;
;	void hijack_warpper_routine( void )
;
;	It's not supposed to be called by code.
;
;	When this routine is reached,
;	the stack is supposed to be:
;	
;	+-----------------------+
;	|		CallContext		|
;	+-----------------------+
;	|	   lpOriContext		|
;	+-----------------------+
;	|	   lpFxsaveArea		|
;	+-----------------------+	<--- May need alignment.
;	|		 Args			|
;	|						|
;	+-----------------------+	<--- Must align to 16.
;	|		FxArea			|	(can be somewhere else)
;	|	  (512 bytes)		|
;	+-----------------------+
;	|		Context			|	(can be somewhere else)
;	|		r0 - r15		|
;	|	 rflags, ori rip	|
;	+-----------------------+
;	|		original		|	(don't touch them any time)
;	|		content			|
;	+-----------------------+
;
;

hijack_warpper_routine proc

	align 16
;	
;	load call context
;	[bug] - after resumed thread, some registers may got corruptted
;
	pop rax
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
	add rsp, 8		;don't overwrite rsp!!
	pop rbp
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15
	popfq

;
;	rbx = function_address
;
	pop rbx

;
;	rsi = lpContext
;	rdi = lpFxsaveArea
;
	pop rsi
	pop rdi

;
;	call the routine
;
	fxsave [rdi]
	call rbx
	fxrstor [rdi]

;
;	now restore the context, 
;	and then return to original
;
	mov rax, [rsi]
	mov rbx, [rsi + 8]
	mov rcx, [rsi + 16]
	mov rdx, [rsi + 24]
; * rsi is saved later *
; * rdi is saved later *
; *	rsp is saved later *
	mov rbp, [rsi + 56]
	mov r8, [rsi + 64]
	mov r9, [rsi + 72]
	mov r10, [rsi + 80]
	mov r11, [rsi + 88]
	mov r12, [rsi + 96]
	mov r13, [rsi + 104]
	mov r14, [rsi + 112]
	mov r15, [rsi + 120]

;
;	restore rflags
;
	mov rdi, [rsi + 128]
	push rdi
	popfq

;	
;	restore left regs and return to original place
;
	mov rdi, [rsi + 136]	; get orig eip first, soon it will be corrupted
	mov rsp, [rsi + 48]
	push rdi				; now orig eip slot is corrupted
	mov rdi, [rsi + 40]
	mov rsi, [rsi + 32]
	ret

	


hijack_warpper_routine endp

end