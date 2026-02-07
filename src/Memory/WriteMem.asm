.code

; SSN = 0x3A
NtWriteVirtualMemory_Syscall PROC
    mov r10, rcx    
    mov eax, 3Ah    
    syscall         
    ret             
NtWriteVirtualMemory_Syscall ENDP

END