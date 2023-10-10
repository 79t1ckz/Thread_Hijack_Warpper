.model flat

public _hijack_warpper_routine

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
;	|	   CallContext		|
;	+-----------------------+
;	|		lpContext		|
;	+-----------------------+
;	|	   lpFxsaveArea		|
;	+-----------------------+	<--- May need alignment.
;	|		 Args			|	(MUST on the stack)
;	|						|
;	+-----------------------+	<--- Must align to 16.
;	|		FxArea			|	(can be somewhere else)
;	|	  (512 bytes)		|
;	+-----------------------+
;	|		Context			|	(can be somewhere else)
;	|		e0 - e7			|
;	|	 eflags, ori eip	|
;	+-----------------------+
;	|		original		|	(don't touch them any time)
;	|		content			|
;	+-----------------------+
;
;

_hijack_warpper_routine proc

	align 16

;
;	get call context
;
	pop eax
	pop ebx
	pop ecx
	pop edx
	pop esi
	pop edi
	add esp, 4	; don't overwrite esp!!
	pop ebp
	popfd

;
;	ebx = func_address
;
	pop ebx

;
;	esi = lpContext
;	edi = lpFxsaveArea
;
	pop esi
	pop edi

;
;	call the routine
;
	fxsave [edi]
	call ebx
	fxrstor [edi]

;
;	now restore the context, 
;	and then return to original
;
	mov eax, [esi]
	mov ebx, [esi + 4]
	mov ecx, [esi + 8]
	mov edx, [esi + 12]
; * esi is saved later *
; * edi is saved later *
; * esp is saved later *
	mov ebp, [esi + 28]

;	
;	restore eflags
;
	mov edi, [esi + 32]
	push edi
	popfd

;	
;	restore left regs and return to original place
;
	mov edi, [esi + 36]		; get orig eip first, soon it will be corrupted
	mov esp, [esi + 24]
	push edi				; now orig eip slot is corrupted
	mov edi, [esi + 20]
	mov esi, [esi + 16]
	ret

	


_hijack_warpper_routine endp

end