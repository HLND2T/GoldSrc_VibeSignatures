---
title: czp-format.windows
type: note
permalink: goldsrc-vibesignatures/evidence/career-storage/czp-format.windows
---

# CZP Windows hl-10210 machine evidence

Module `gameui`; PE image base `0x10000000`. SHA-256 is bound in `hl-10210.windows.json`. These are static instructions, not runtime validation.

## CreateProfileBuffer

```asm
0x10019c50 push    ebp
0x10019c51 mov     ebp, esp
0x10019c53 sub     esp, 408h
0x10019c59 mov     eax, ___security_cookie
0x10019c5e xor     eax, ebp
0x10019c60 mov     [ebp+var_4], eax
0x10019c63 mov     eax, [ebp+arg_4]
0x10019c66 push    ebx
0x10019c67 mov     ebx, [ebp+arg_0]
0x10019c6a push    esi
0x10019c6b push    edi
0x10019c6c push    [ebp+arg_8]
0x10019c6f mov     edi, ecx
0x10019c71 mov     [ebp+var_408], eax
0x10019c77 push    eax
0x10019c78 mov     ecx, [edi+8]
0x10019c7b call    sub_10001950
0x10019c80 mov     ecx, [edi+8]
0x10019c83 push    offset aCzp; "CZP"
0x10019c88 call    sub_10001B50
0x10019c8d mov     ecx, [edi+8]
0x10019c90 push    4
0x10019c92 call    sub_10001B00
0x10019c97 cmp     dword ptr [ebx+18h], 10h
0x10019c9b lea     eax, [ebx+4]
0x10019c9e jb      short loc_10019CA2
0x10019ca0 mov     eax, [eax]
0x10019ca2 mov     ecx, [edi+8]
0x10019ca5 push    eax
0x10019ca6 call    sub_10001B50
0x10019cab push    dword ptr [ebx+1Ch]
0x10019cae mov     ecx, [edi+8]
0x10019cb1 call    sub_10001B00
0x10019cb6 movzx   eax, byte ptr [ebx+20h]
0x10019cba mov     ecx, [edi+8]
0x10019cbd push    eax
0x10019cbe call    sub_10001AD0
0x10019cc3 xor     esi, esi
0x10019cc5 movzx   eax, byte ptr [ebx+esi+24h]
0x10019cca mov     ecx, [edi+8]
0x10019ccd push    eax
0x10019cce call    sub_10001AD0
0x10019cd3 inc     esi
0x10019cd4 cmp     esi, 4
0x10019cd7 jl      short loc_10019CC5
0x10019cd9 lea     esi, [ebx+28h]
0x10019cdc mov     ebx, 4
0x10019ce1 push    esi
0x10019ce2 mov     ecx, edi
0x10019ce4 call    sub_1001ACE0
0x10019ce9 add     esi, 3Ch ; '<'
0x10019cec sub     ebx, 1
0x10019cef jnz     short loc_10019CE1
0x10019cf1 lea     eax, [ebp+var_404]
0x10019cf7 cmp     [ebp+arg_C], bl
0x10019cfa jz      short loc_10019D0D
0x10019cfc push    400h; Size
0x10019d01 push    ebx; Val
0x10019d02 push    eax; void *
0x10019d03 call    memset
0x10019d08 add     esp, 0Ch
0x10019d0b jmp     short loc_10019D23
0x10019d0d push    100h
0x10019d12 push    eax
0x10019d13 mov     eax, dword_100C30C0
0x10019d18 mov     eax, [eax+1FCh]
0x10019d1e call    eax
0x10019d20 add     esp, 8
0x10019d23 mov     ecx, [edi+8]
0x10019d26 push    100h
0x10019d2b call    sub_10001B00
0x10019d30 xor     esi, esi
0x10019d32 nop     dword ptr [eax+00h]
0x10019d36 nop     word ptr [eax+eax+00000000h]
0x10019d40 push    [ebp+esi*4+var_404]
0x10019d47 mov     ecx, [edi+8]
0x10019d4a call    sub_10001B00
0x10019d4f inc     esi
0x10019d50 cmp     esi, 100h
0x10019d56 jl      short loc_10019D40
0x10019d58 mov     ecx, [edi+8]
0x10019d5b call    sub_10001940
0x10019d60 push    eax
0x10019d61 push    [ebp+var_408]
0x10019d67 call    sub_10019910
0x10019d6c mov     ecx, [edi+8]
0x10019d6f add     esp, 8
0x10019d72 push    eax
0x10019d73 call    sub_10001B00
0x10019d78 mov     ecx, [edi+8]
0x10019d7b call    sub_10001940
0x10019d80 mov     ecx, [ebp+var_4]
0x10019d83 pop     edi
0x10019d84 pop     esi
0x10019d85 xor     ecx, ebp; StackCookie
0x10019d87 pop     ebx
0x10019d88 call    @__security_check_cookie@4; __security_check_cookie(x)
0x10019d8d mov     esp, ebp
0x10019d8f pop     ebp
0x10019d90 retn    10h
```

## ParseSavedProfile

```asm
0x1001a560 push    ebp
0x1001a561 mov     ebp, esp
0x1001a563 sub     esp, 8
0x1001a566 push    ebx
0x1001a567 push    esi
0x1001a568 mov     esi, [ebp+arg_0]
0x1001a56b mov     [ebp+var_8], ecx
0x1001a56e push    edi
0x1001a56f test    esi, esi
0x1001a571 jz      loc_1001A70D
0x1001a577 mov     ebx, [ebp+arg_4]
0x1001a57a cmp     ebx, 5
0x1001a57d jl      loc_1001A70D
0x1001a583 mov     edi, [ebp+arg_8]
0x1001a586 test    edi, edi
0x1001a588 jz      loc_1001A70D
0x1001a58e mov     ecx, edi
0x1001a590 call    sub_1001A790
0x1001a595 push    ebx
0x1001a596 push    esi
0x1001a597 call    sub_10001910
0x1001a59c add     esp, 8
0x1001a59f call    sub_10001A60
0x1001a5a4 test    eax, eax
0x1001a5a6 jz      loc_1001A70D
0x1001a5ac mov     ecx, offset aCzp; "CZP"
0x1001a5b1 mov     dl, [eax]
0x1001a5b3 cmp     dl, [ecx]
0x1001a5b5 jnz     short loc_1001A5D1
0x1001a5b7 test    dl, dl
0x1001a5b9 jz      short loc_1001A5CD
0x1001a5bb mov     dl, [eax+1]
0x1001a5be cmp     dl, [ecx+1]
0x1001a5c1 jnz     short loc_1001A5D1
0x1001a5c3 add     eax, 2
0x1001a5c6 add     ecx, 2
0x1001a5c9 test    dl, dl
0x1001a5cb jnz     short loc_1001A5B1
0x1001a5cd xor     eax, eax
0x1001a5cf jmp     short loc_1001A5D6
0x1001a5d1 sbb     eax, eax
0x1001a5d3 or      eax, 1
0x1001a5d6 test    eax, eax
0x1001a5d8 jnz     loc_1001A70D
0x1001a5de call    sub_100019A0
0x1001a5e3 mov     ebx, eax
0x1001a5e5 mov     [ebp+var_4], ebx
0x1001a5e8 lea     ecx, [ebx-1]
0x1001a5eb cmp     ecx, 3
0x1001a5ee ja      loc_1001A700
0x1001a5f4 call    sub_10001A60
0x1001a5f9 push    eax; Src
0x1001a5fa lea     ecx, [edi+4]; void *
0x1001a5fd call    sub_100192D0
0x1001a602 call    sub_100019A0
0x1001a607 mov     [edi+1Ch], eax
0x1001a60a cmp     ebx, 4
0x1001a60d jl      short loc_1001A620
0x1001a60f call    sub_10001970
0x1001a614 mov     [edi+20h], eax
0x1001a617 test    eax, eax
0x1001a619 js      short loc_1001A620
0x1001a61b cmp     eax, 3
0x1001a61e jle     short loc_1001A627
0x1001a620 mov     dword ptr [edi+20h], 0
0x1001a627 call    sub_10001A00
0x1001a62c test    eax, eax
0x1001a62e setnz   bl
0x1001a631 test    eax, eax
0x1001a633 jz      short loc_1001A655
0x1001a635 xor     esi, esi
0x1001a637 call    sub_10001970
0x1001a63c test    eax, eax
0x1001a63e setnz   al
0x1001a641 mov     [edi+esi+24h], al
0x1001a645 inc     esi
0x1001a646 cmp     esi, 4
0x1001a649 jl      short loc_1001A637
0x1001a64b call    sub_10001A00
0x1001a650 test    eax, eax
0x1001a652 setnz   bl
0x1001a655 lea     esi, [edi+28h]
0x1001a658 mov     edi, 4
0x1001a65d nop     dword ptr [eax]
0x1001a660 test    bl, bl
0x1001a662 jz      short loc_1001A672
0x1001a664 push    [ebp+var_4]
0x1001a667 mov     ecx, [ebp+var_8]
0x1001a66a push    esi
0x1001a66b call    sub_1001A2C0
0x1001a670 mov     bl, al
0x1001a672 add     esi, 3Ch ; '<'
0x1001a675 sub     edi, 1
0x1001a678 jnz     short loc_1001A660
0x1001a67a test    bl, bl
0x1001a67c jz      short loc_1001A6F0
0x1001a67e mov     edi, [ebp+arg_8]
0x1001a681 push    400h; Size
0x1001a686 add     edi, 118h
0x1001a68c push    0; Val
0x1001a68e push    edi; void *
0x1001a68f call    memset
0x1001a694 add     esp, 0Ch
0x1001a697 cmp     [ebp+var_4], 1
0x1001a69b jz      short loc_1001A6C7
0x1001a69d call    sub_100019A0
0x1001a6a2 mov     ebx, eax
0x1001a6a4 xor     esi, esi
0x1001a6a6 test    ebx, ebx
0x1001a6a8 jle     short loc_1001A6C7
0x1001a6aa nop     word ptr [eax+eax+00h]
0x1001a6b0 call    sub_100019A0
0x1001a6b5 cmp     esi, 100h
0x1001a6bb jnb     short loc_1001A6BF
0x1001a6bd mov     [edi], eax
0x1001a6bf inc     esi
0x1001a6c0 add     edi, 4
0x1001a6c3 cmp     esi, ebx
0x1001a6c5 jl      short loc_1001A6B0
0x1001a6c7 call    sub_100019A0
0x1001a6cc mov     ecx, [ebp+arg_4]
0x1001a6cf mov     esi, eax
0x1001a6d1 add     ecx, 0FFFFFFFCh
0x1001a6d4 push    ecx
0x1001a6d5 push    [ebp+arg_0]
0x1001a6d8 call    sub_10019910
0x1001a6dd add     esp, 8
0x1001a6e0 cmp     esi, eax
0x1001a6e2 setz    bl
0x1001a6e5 mov     al, bl
0x1001a6e7 pop     edi
0x1001a6e8 pop     esi
0x1001a6e9 pop     ebx
0x1001a6ea mov     esp, ebp
0x1001a6ec pop     ebp
0x1001a6ed retn    0Ch
0x1001a6f0 call    sub_100019A0
0x1001a6f5 pop     edi
0x1001a6f6 pop     esi
0x1001a6f7 mov     al, bl
0x1001a6f9 pop     ebx
0x1001a6fa mov     esp, ebp
0x1001a6fc pop     ebp
0x1001a6fd retn    0Ch
0x1001a700 pop     edi
0x1001a701 xor     bl, bl
0x1001a703 pop     esi
0x1001a704 mov     al, bl
0x1001a706 pop     ebx
0x1001a707 mov     esp, ebp
0x1001a709 pop     ebp
0x1001a70a retn    0Ch
0x1001a70d pop     edi
0x1001a70e pop     esi
0x1001a70f xor     al, al
0x1001a711 pop     ebx
0x1001a712 mov     esp, ebp
0x1001a714 pop     ebp
0x1001a715 retn    0Ch
```

## Checksum

```asm
0x10019910 push    ebp
0x10019911 mov     ebp, esp
0x10019913 sub     esp, 8
0x10019916 mov     edx, [ebp+arg_4]
0x10019919 xor     ecx, ecx
0x1001991b push    ebx
0x1001991c push    esi
0x1001991d push    edi
0x1001991e lea     eax, [ecx+1]
0x10019921 mov     [ebp+var_4], ecx
0x10019924 cmp     edx, eax
0x10019926 jl      loc_100199D1
0x1001992c cmp     edx, 8
0x1001992f jb      loc_100199D1
0x10019935 cmp     dword_100CADAC, 2
0x1001993c jl      loc_100199D1
0x10019942 movaps  xmm4, ds:xmmword_10090880
0x10019949 mov     edi, edx
0x1001994b mov     esi, [ebp+arg_0]
0x1001994e and     edi, 0FFFFFFF8h
0x10019951 xorps   xmm3, xmm3
0x10019954 xorps   xmm2, xmm2
0x10019957 nop     word ptr [eax+eax+00000000h]
0x10019960 movd    xmm0, eax
0x10019964 lea     ecx, [eax+4]
0x10019967 pshufd  xmm1, xmm0, 0
0x1001996c add     eax, 8
0x1001996f movd    xmm0, dword ptr [esi]
0x10019973 paddd   xmm1, xmm4
0x10019977 pmovzxbd xmm0, xmm0
0x1001997c pmulld  xmm0, xmm1
0x10019981 paddd   xmm3, xmm0
0x10019985 movd    xmm0, ecx
0x10019989 pshufd  xmm1, xmm0, 0
0x1001998e movd    xmm0, dword ptr [esi+4]
0x10019993 paddd   xmm1, xmm4
0x10019997 pmovzxbd xmm0, xmm0
0x1001999c pmulld  xmm0, xmm1
0x100199a1 add     esi, 8
0x100199a4 paddd   xmm2, xmm0
0x100199a8 cmp     eax, edi
0x100199aa jle     short loc_10019960
0x100199ac paddd   xmm2, xmm3
0x100199b0 movaps  xmm0, xmm2
0x100199b3 psrldq  xmm0, 8
0x100199b8 paddd   xmm2, xmm0
0x100199bc movups  xmm0, xmm2
0x100199bf psrldq  xmm0, 4
0x100199c4 paddd   xmm2, xmm0
0x100199c8 movd    ecx, xmm2
0x100199cc mov     [ebp+var_4], ecx
0x100199cf jmp     short loc_100199D4
0x100199d1 mov     esi, [ebp+arg_0]
0x100199d4 xor     edi, edi
0x100199d6 xor     ebx, ebx
0x100199d8 cmp     eax, edx
0x100199da jg      short loc_10019A3C
0x100199dc mov     ecx, edx
0x100199de sub     ecx, eax
0x100199e0 inc     ecx
0x100199e1 cmp     ecx, 2
0x100199e4 jl      short loc_10019A16
0x100199e6 lea     ecx, [edx-1]
0x100199e9 mov     [ebp+var_8], ecx
0x100199ec nop     dword ptr [eax+00h]
0x100199f0 movzx   ecx, byte ptr [esi]
0x100199f3 movzx   edx, byte ptr [esi+1]
0x100199f7 add     esi, 2
0x100199fa imul    ecx, eax
0x100199fd add     edi, ecx
0x100199ff lea     ecx, [eax+1]
0x10019a02 imul    edx, ecx
0x10019a05 add     eax, 2
0x10019a08 mov     ecx, eax
0x10019a0a add     ebx, edx
0x10019a0c cmp     eax, [ebp+var_8]
0x10019a0f jle     short loc_100199F0
0x10019a11 cmp     ecx, [ebp+arg_4]
0x10019a14 jg      short loc_10019A2D
0x10019a16 movzx   ecx, byte ptr [esi]
0x10019a19 imul    ecx, eax
0x10019a1c mov     eax, [ebp+var_4]
0x10019a1f add     eax, ecx
0x10019a21 lea     ecx, [ebx+edi]
0x10019a24 pop     edi
0x10019a25 pop     esi
0x10019a26 add     eax, ecx
0x10019a28 pop     ebx
0x10019a29 mov     esp, ebp
0x10019a2b pop     ebp
0x10019a2c retn
0x10019a2d mov     eax, [ebp+var_4]
0x10019a30 lea     ecx, [ebx+edi]
0x10019a33 pop     edi
0x10019a34 pop     esi
0x10019a35 add     eax, ecx
0x10019a37 pop     ebx
0x10019a38 mov     esp, ebp
0x10019a3a pop     ebp
0x10019a3b retn
0x10019a3c pop     edi
0x10019a3d pop     esi
0x10019a3e mov     eax, ecx
0x10019a40 pop     ebx
0x10019a41 mov     esp, ebp
0x10019a43 pop     ebp
0x10019a44 retn
```

## WriteString

```asm
0x10001b50 push    ebp
0x10001b51 mov     ebp, esp
0x10001b53 push    esi
0x10001b54 mov     esi, ecx
0x10001b56 mov     edx, [esi]
0x10001b58 test    edx, edx
0x10001b5a jz      short loc_10001BAF
0x10001b5c cmp     dword ptr [esi+4], 0
0x10001b60 jz      short loc_10001BAF
0x10001b62 mov     eax, [ebp+arg_0]
0x10001b65 mov     ecx, offset Src
0x10001b6a test    eax, eax
0x10001b6c push    edi
0x10001b6d cmovnz  ecx, eax
0x10001b70 mov     edi, ecx
0x10001b72 lea     eax, [edi+1]
0x10001b75 mov     [ebp+arg_0], eax
0x10001b78 mov     al, [edi]
0x10001b7a inc     edi
0x10001b7b test    al, al
0x10001b7d jnz     short loc_10001B78
0x10001b7f sub     edi, [ebp+arg_0]
0x10001b82 inc     edi
0x10001b83 cmp     edi, [esi+4]
0x10001b86 jle     short loc_10001B96
0x10001b88 mov     byte ptr [esi+8], 1
0x10001b8c mov     ecx, offset Src
0x10001b91 mov     edi, 1
0x10001b96 mov     al, [ecx]
0x10001b98 lea     ecx, [ecx+1]
0x10001b9b mov     [edx], al
0x10001b9d lea     edx, [edx+1]
0x10001ba0 test    al, al
0x10001ba2 jnz     short loc_10001B96
0x10001ba4 sub     [esi+4], edi
0x10001ba7 add     [esi], edi
0x10001ba9 pop     edi
0x10001baa pop     esi
0x10001bab pop     ebp
0x10001bac retn    4
0x10001baf mov     byte ptr [esi+8], 1
0x10001bb3 pop     esi
0x10001bb4 pop     ebp
0x10001bb5 retn    4
```

## WriteLong

```asm
0x10001b00 push    ebp
0x10001b01 mov     ebp, esp
0x10001b03 push    esi
0x10001b04 mov     esi, ecx
0x10001b06 mov     eax, [esi]
0x10001b08 test    eax, eax
0x10001b0a jz      short loc_10001B3F
0x10001b0c cmp     dword ptr [esi+4], 4
0x10001b10 jl      short loc_10001B3F
0x10001b12 mov     edx, [ebp+arg_0]
0x10001b15 mov     ecx, edx
0x10001b17 mov     [eax], dl
0x10001b19 mov     eax, [esi]
0x10001b1b sar     ecx, 8
0x10001b1e mov     [eax+1], cl
0x10001b21 mov     ecx, edx
0x10001b23 mov     eax, [esi]
0x10001b25 sar     ecx, 10h
0x10001b28 sar     edx, 18h
0x10001b2b mov     [eax+2], cl
0x10001b2e mov     eax, [esi]
0x10001b30 mov     [eax+3], dl
0x10001b33 add     dword ptr [esi], 4
0x10001b36 add     dword ptr [esi+4], 0FFFFFFFCh
0x10001b3a pop     esi
0x10001b3b pop     ebp
0x10001b3c retn    4
0x10001b3f mov     byte ptr [esi+8], 1
0x10001b43 pop     esi
0x10001b44 pop     ebp
0x10001b45 retn    4
```

## ReadLong

```asm
0x100019a0 push    esi
0x100019a1 mov     esi, dword_100BB248
0x100019a7 push    edi
0x100019a8 lea     edi, [esi+4]
0x100019ab cmp     edi, dword_100BB244
0x100019b1 jle     short loc_100019C3
0x100019b3 pop     edi
0x100019b4 mov     dword_100BB24C, 1
0x100019be or      eax, 0FFFFFFFFh
0x100019c1 pop     esi
0x100019c2 retn
0x100019c3 mov     eax, dword_100BB240
0x100019c8 mov     dword_100BB248, edi
0x100019ce pop     edi
0x100019cf movzx   edx, byte ptr [eax+esi+3]
0x100019d4 movzx   ecx, byte ptr [eax+esi+2]
0x100019d9 shl     edx, 8
0x100019dc add     edx, ecx
0x100019de movzx   ecx, byte ptr [eax+esi+1]
0x100019e3 movzx   eax, byte ptr [eax+esi]
0x100019e7 shl     edx, 8
0x100019ea add     edx, ecx
0x100019ec shl     edx, 8
0x100019ef add     eax, edx
0x100019f1 pop     esi
0x100019f2 retn
```

## BEGIN_READ

```asm
0x10001910 push    ebp
0x10001911 mov     ebp, esp
0x10001913 mov     eax, [ebp+arg_4]
0x10001916 mov     dword_100BB244, eax
0x1000191b mov     eax, [ebp+arg_0]
0x1000191e mov     dword_100BB248, 0
0x10001928 mov     dword_100BB24C, 0
0x10001932 mov     dword_100BB240, eax
0x10001937 pop     ebp
0x10001938 retn
```

## GameUI filesystem interface acquisition

```text
bool __cdecl sub_100508A0(char *Source, int a2, int a3)
{
  int v3; // ebx
  int (__cdecl *v4)(const char *, _DWORD); // eax
  int v5; // eax
  int v6; // ebx
  int (__cdecl *v7)(const char *, _DWORD); // eax
  int v8; // eax
  int v9; // ebx
  int (__cdecl *v10)(const char *, _DWORD); // eax
  int v11; // eax
  int v12; // ebx
  int (__cdecl *v13)(const char *, _DWORD); // eax
  int v14; // eax
  int v15; // ebx
  int (__cdecl *v16)(const char *, _DWORD); // eax
  int v17; // eax
  int v18; // ebx
  int (__cdecl *v19)(const char *, _DWORD); // eax
  int v20; // eax
  int v21; // ebx
  int (__cdecl *v22)(const char *, _DWORD); // eax
  int v23; // eax
  int v24; // ebx
  int (__cdecl *v25)(const char *, _DWORD); // eax
  int v26; // eax
  int v27; // ebx
  int (__cdecl *v28)(const char *, _DWORD); // eax
  int v29; // eax
  int v30; // ecx

  strncpy(byte_100C6B78, Source, 0x100u);
  byte_100C6C77 = 0;
  setlocale(2, Src);
  setlocale(5, Src);
  setlocale(1, Src);
  setlocale(3, Src);
  v3 = 0;
  if ( a3 > 0 )
  {
    while ( 1 )
    {
      v4 = *(int (__cdecl **)(const char *, _DWORD))(a2 + 4 * v3);
      if ( v4 )
      {
        v5 = v4("VGUI_ivgui006", 0);
        if ( v5 )
          break;
      }
      if ( ++v3 >= a3 )
        goto LABEL_5;
    }
    dword_100C6B64 = v5;
    goto LABEL_6;
  }
LABEL_5:
  dword_100C6B64 = 0;
  if ( a3 > 0 )
  {
LABEL_6:
    v6 = 0;
    while ( 1 )
    {
      v7 = *(int (__cdecl **)(const char *, _DWORD))(a2 + 4 * v6);
      if ( v7 )
      {
        v8 = v7("VGUI_Panel007", 0);
        if ( v8 )
          break;
      }
      if ( ++v6 >= a3 )
        goto LABEL_10;
    }
    dword_100C6B68 = v8;
    goto LABEL_11;
  }
LABEL_10:
  dword_100C6B68 = 0;
  if ( a3 > 0 )
  {
LABEL_11:
    v9 = 0;
    while ( 1 )
    {
      v10 = *(int (__cdecl **)(const char *, _DWORD))(a2 + 4 * v9);
      if ( v10 )
      {
        v11 = v10("VGUI_Surface026", 0);
        if ( v11 )
          break;
      }
      if ( ++v9 >= a3 )
        goto LABEL_15;
    }
    dword_100C6B5C = v11;
    goto LABEL_16;
  }
LABEL_15:
  dword_100C6B5C = 0;
  if ( a3 > 0 )
  {
LABEL_16:
    v12 = 0;
    while ( 1 )
    {
      v13 = *(int (__cdecl **)(const char *, _DWORD))(a2 + 4 * v12);
      if ( v13 )
      {
        v14 = v13("VGUI_Scheme009", 0);
        if ( v14 )
          break;
      }
      if ( ++v12 >= a3 )
        goto LABEL_20;
    }
    dword_100C6B58 = v14;
    goto LABEL_21;
  }
LABEL_20:
  dword_100C6B58 = 0;
  if ( a3 > 0 )
  {
LABEL_21:
    v15 = 0;
    while ( 1 )
    {
      v16 = *(int (__cdecl **)(const char *, _DWORD))(a2 + 4 * v15);
      if ( v16 )
      {
        v17 = v16("VGUI_System009", 0);
        if ( v17 )
          break;
      }
      if ( ++v15 >= a3 )
        goto LABEL_25;
    }
    dword_100C6B60 = v17;
    goto LABEL_26;
  }
LABEL_25:
  dword_100C6B60 = 0;
  if ( a3 > 0 )
  {
LABEL_26:
    v18 = 0;
    while ( 1 )
    {
      v19 = *(int (__cdecl **)(const char *, _DWORD))(a2 + 4 * v18);
      if ( v19 )
      {
        v20 = v19("VGUI_Input004", 0);
        if ( v20 )
          break;
      }
      if ( ++v18 >= a3 )
        goto LABEL_30;
    }
    dword_100C6B54 = v20;
    goto LABEL_31;
  }
LABEL_30:
  dword_100C6B54 = 0;
  if ( a3 > 0 )
  {
LABEL_31:
    v21 = 0;
    while ( 1 )
    {
      v22 = *(int (__cdecl **)(const char *, _DWORD))(a2 + 4 * v21);
      if ( v22 )
      {
        v23 = v22("VGUI_Localize003", 0);
        if ( v23 )
          break;
      }
      if ( ++v21 >= a3 )
        goto LABEL_35;
    }
    dword_100C6B70 = v23;
    goto LABEL_36;
  }
LABEL_35:
  dword_100C6B70 = 0;
  if ( a3 > 0 )
  {
LABEL_36:
    v24 = 0;
    while ( 1 )
    {
      v25 = *(int (__cdecl **)(const char *, _DWORD))(a2 + 4 * v24);
      if ( v25 )
      {
        v26 = v25("VFileSystem009", 0);
        if ( v26 )
          break;
      }
      if ( ++v24 >= a3 )
        goto LABEL_40;
    }
    dword_100C6B6C = v26;
    goto LABEL_41;
  }
LABEL_40:
  dword_100C6B6C = 0;
  if ( a3 <= 0 )
  {
LABEL_45:
    v29 = 0;
    goto LABEL_46;
  }
LABEL_41:
  v27 = 0;
  while ( 1 )
  {
    v28 = *(int (__cdecl **)(const char *, _DWORD))(a2 + 4 * v27);
    if ( v28 )
    {
      v29 = v28("KeyValues003", 0);
      if ( v29 )
        break;
    }
    if ( ++v27 >= a3 )
      goto LABEL_45;
  }
LABEL_46:
  dword_100C6B50 = v29;
  if ( !dword_100C6B64 )
    return 0;
  (*(void (__thiscall **)(int, int, int))(*(_DWORD *)dword_100C6B64 + 4))(dword_100C6B64, a2, a3);
  v30 = dword_100C6B50;
  if ( dword_100C6B50 )
  {
    (*(void (__thiscall **)(int, int))(*(_DWORD *)dword_100C6B50 + 4))(dword_100C6B50, 24);
    v30 = dword_100C6B50;
  }
  return dword_100C6B58
      && dword_100C6B5C
      && dword_100C6B60
      && dword_100C6B54
      && dword_100C6B64
      && dword_100C6B6C
      && dword_100C6B70
      && v30
      && dword_100C6B68;
}


0x100508a0 push    ebp
0x100508a1 mov     ebp, esp
0x100508a3 push    ebx
0x100508a4 push    esi
0x100508a5 push    edi
0x100508a6 push    100h; Count
0x100508ab push    [ebp+Source]; Source
0x100508ae push    offset byte_100C6B78; Destination
0x100508b3 call    ds:strncpy
0x100508b9 mov     esi, ds:setlocale
0x100508bf push    offset Src; Locale
0x100508c4 push    2; Category
0x100508c6 mov     byte_100C6C77, 0
0x100508cd call    esi ; setlocale
0x100508cf push    offset Src; Locale
0x100508d4 push    5; Category
0x100508d6 call    esi ; setlocale
0x100508d8 push    offset Src; Locale
0x100508dd push    1; Category
0x100508df call    esi ; setlocale
0x100508e1 push    offset Src; Locale
0x100508e6 push    3; Category
0x100508e8 call    esi ; setlocale
0x100508ea mov     esi, [ebp+arg_8]
0x100508ed add     esp, 2Ch
0x100508f0 mov     edi, [ebp+arg_4]
0x100508f3 xor     ebx, ebx
0x100508f5 test    esi, esi
0x100508f7 jle     short loc_10050920
0x100508f9 nop     dword ptr [eax+00000000h]
0x10050900 mov     eax, [edi+ebx*4]
0x10050903 test    eax, eax
0x10050905 jz      short loc_1005091B
0x10050907 push    0
0x10050909 push    offset aVguiIvgui006; "VGUI_ivgui006"
0x1005090e call    eax
0x10050910 add     esp, 8
0x10050913 test    eax, eax
0x10050915 jnz     loc_10050B32
0x1005091b inc     ebx
0x1005091c cmp     ebx, esi
0x1005091e jl      short loc_10050900
0x10050920 mov     dword_100C6B64, 0
0x1005092a test    esi, esi
0x1005092c jle     short loc_10050950
0x1005092e xor     ebx, ebx
0x10050930 mov     eax, [edi+ebx*4]
0x10050933 test    eax, eax
0x10050935 jz      short loc_1005094B
0x10050937 push    0
0x10050939 push    offset aVguiPanel007; "VGUI_Panel007"
0x1005093e call    eax
0x10050940 add     esp, 8
0x10050943 test    eax, eax
0x10050945 jnz     loc_10050B3C
0x1005094b inc     ebx
0x1005094c cmp     ebx, esi
0x1005094e jl      short loc_10050930
0x10050950 mov     dword_100C6B68, 0
0x1005095a test    esi, esi
0x1005095c jle     short loc_10050980
0x1005095e xor     ebx, ebx
0x10050960 mov     eax, [edi+ebx*4]
0x10050963 test    eax, eax
0x10050965 jz      short loc_1005097B
0x10050967 push    0
0x10050969 push    offset aVguiSurface026; "VGUI_Surface026"
0x1005096e call    eax
0x10050970 add     esp, 8
0x10050973 test    eax, eax
0x10050975 jnz     loc_10050B46
0x1005097b inc     ebx
0x1005097c cmp     ebx, esi
0x1005097e jl      short loc_10050960
0x10050980 mov     dword_100C6B5C, 0
0x1005098a test    esi, esi
0x1005098c jle     short loc_100509B0
0x1005098e xor     ebx, ebx
0x10050990 mov     eax, [edi+ebx*4]
0x10050993 test    eax, eax
0x10050995 jz      short loc_100509AB
0x10050997 push    0
0x10050999 push    offset aVguiScheme009; "VGUI_Scheme009"
0x1005099e call    eax
0x100509a0 add     esp, 8
0x100509a3 test    eax, eax
0x100509a5 jnz     loc_10050B50
0x100509ab inc     ebx
0x100509ac cmp     ebx, esi
0x100509ae jl      short loc_10050990
0x100509b0 mov     dword_100C6B58, 0
0x100509ba test    esi, esi
0x100509bc jle     short loc_100509E0
0x100509be xor     ebx, ebx
0x100509c0 mov     eax, [edi+ebx*4]
0x100509c3 test    eax, eax
0x100509c5 jz      short loc_100509DB
0x100509c7 push    0
0x100509c9 push    offset aVguiSystem009; "VGUI_System009"
0x100509ce call    eax
0x100509d0 add     esp, 8
0x100509d3 test    eax, eax
0x100509d5 jnz     loc_10050B5A
0x100509db inc     ebx
0x100509dc cmp     ebx, esi
0x100509de jl      short loc_100509C0
0x100509e0 mov     dword_100C6B60, 0
0x100509ea test    esi, esi
0x100509ec jle     short loc_10050A10
0x100509ee xor     ebx, ebx
0x100509f0 mov     eax, [edi+ebx*4]
0x100509f3 test    eax, eax
0x100509f5 jz      short loc_10050A0B
0x100509f7 push    0
0x100509f9 push    offset aVguiInput004; "VGUI_Input004"
0x100509fe call    eax
0x10050a00 add     esp, 8
0x10050a03 test    eax, eax
0x10050a05 jnz     loc_10050B64
0x10050a0b inc     ebx
0x10050a0c cmp     ebx, esi
0x10050a0e jl      short loc_100509F0
0x10050a10 mov     dword_100C6B54, 0
0x10050a1a test    esi, esi
0x10050a1c jle     short loc_10050A40
0x10050a1e xor     ebx, ebx
0x10050a20 mov     eax, [edi+ebx*4]
0x10050a23 test    eax, eax
0x10050a25 jz      short loc_10050A3B
0x10050a27 push    0
0x10050a29 push    offset aVguiLocalize00; "VGUI_Localize003"
0x10050a2e call    eax
0x10050a30 add     esp, 8
0x10050a33 test    eax, eax
0x10050a35 jnz     loc_10050B6E
0x10050a3b inc     ebx
0x10050a3c cmp     ebx, esi
0x10050a3e jl      short loc_10050A20
0x10050a40 mov     dword_100C6B70, 0
0x10050a4a test    esi, esi
0x10050a4c jle     short loc_10050A70
0x10050a4e xor     ebx, ebx
0x10050a50 mov     eax, [edi+ebx*4]
0x10050a53 test    eax, eax
0x10050a55 jz      short loc_10050A6B
0x10050a57 push    0
0x10050a59 push    offset aVfilesystem009; "VFileSystem009"
0x10050a5e call    eax
0x10050a60 add     esp, 8
0x10050a63 test    eax, eax
0x10050a65 jnz     loc_10050B78
0x10050a6b inc     ebx
0x10050a6c cmp     ebx, esi
0x10050a6e jl      short loc_10050A50
0x10050a70 mov     dword_100C6B6C, 0
0x10050a7a test    esi, esi
0x10050a7c jle     short loc_10050A9C
0x10050a7e xor     ebx, ebx
0x10050a80 mov     eax, [edi+ebx*4]
0x10050a83 test    eax, eax
0x10050a85 jz      short loc_10050A97
0x10050a87 push    0
0x10050a89 push    offset aKeyvalues003; "KeyValues003"
0x10050a8e call    eax
0x10050a90 add     esp, 8
0x10050a93 test    eax, eax
0x10050a95 jnz     short loc_10050A9E
0x10050a97 inc     ebx
0x10050a98 cmp     ebx, esi
0x10050a9a jl      short loc_10050A80
0x10050a9c xor     eax, eax
0x10050a9e mov     ecx, dword_100C6B64
0x10050aa4 mov     dword_100C6B50, eax
0x10050aa9 test    ecx, ecx
0x10050aab jz      loc_10050B82
0x10050ab1 mov     eax, [ecx]
0x10050ab3 push    esi
0x10050ab4 push    edi
0x10050ab5 call    dword ptr [eax+4]
0x10050ab8 mov     ecx, dword_100C6B50
0x10050abe test    ecx, ecx
0x10050ac0 jz      short loc_10050ACF
0x10050ac2 mov     eax, [ecx]
0x10050ac4 push    18h
0x10050ac6 call    dword ptr [eax+4]
0x10050ac9 mov     ecx, dword_100C6B50
0x10050acf cmp     dword_100C6B58, 0
0x10050ad6 jz      loc_10050B82
0x10050adc cmp     dword_100C6B5C, 0
0x10050ae3 jz      loc_10050B82
0x10050ae9 cmp     dword_100C6B60, 0
0x10050af0 jz      loc_10050B82
0x10050af6 cmp     dword_100C6B54, 0
0x10050afd jz      loc_10050B82
0x10050b03 cmp     dword_100C6B64, 0
0x10050b0a jz      short loc_10050B82
0x10050b0c cmp     dword_100C6B6C, 0
0x10050b13 jz      short loc_10050B82
0x10050b15 cmp     dword_100C6B70, 0
0x10050b1c jz      short loc_10050B82
0x10050b1e test    ecx, ecx
0x10050b20 jz      short loc_10050B82
0x10050b22 cmp     dword_100C6B68, 0
0x10050b29 jz      short loc_10050B82
0x10050b2b pop     edi
0x10050b2c pop     esi
0x10050b2d mov     al, 1
0x10050b2f pop     ebx
0x10050b30 pop     ebp
0x10050b31 retn
0x10050b32 mov     dword_100C6B64, eax
0x10050b37 jmp     loc_1005092E
0x10050b3c mov     dword_100C6B68, eax
0x10050b41 jmp     loc_1005095E
0x10050b46 mov     dword_100C6B5C, eax
0x10050b4b jmp     loc_1005098E
0x10050b50 mov     dword_100C6B58, eax
0x10050b55 jmp     loc_100509BE
0x10050b5a mov     dword_100C6B60, eax
0x10050b5f jmp     loc_100509EE
0x10050b64 mov     dword_100C6B54, eax
0x10050b69 jmp     loc_10050A1E
0x10050b6e mov     dword_100C6B70, eax
0x10050b73 jmp     loc_10050A4E
0x10050b78 mov     dword_100C6B6C, eax
0x10050b7d jmp     loc_10050A7E
0x10050b82 pop     edi
0x10050b83 pop     esi
0x10050b84 xor     al, al
0x10050b86 pop     ebx
0x10050b87 pop     ebp
0x10050b88 retn
```
## sprintf varargs wrapper: cdecl(dst,format,...), EAX int, caller cleanup

```asm
0x10003660 push    ebp
0x10003661 mov     ebp, esp
0x10003663 lea     eax, [ebp+ArgList]
0x10003666 push    eax; ArgList
0x10003667 push    0; Locale
0x10003669 push    [ebp+Format]; Format
0x1000366c push    0FFFFFFFFh; BufferCount
0x1000366e push    [ebp+Buffer]; Buffer
0x10003671 call    sub_10003610
0x10003676 mov     ecx, [eax]
0x10003678 push    dword ptr [eax+4]
0x1000367b or      ecx, 1
0x1000367e push    ecx; Options
0x1000367f call    ds:__stdio_common_vsprintf
0x10003685 or      ecx, 0FFFFFFFFh
0x10003688 add     esp, 1Ch
0x1000368b test    eax, eax
0x1000368d cmovs   eax, ecx
0x10003690 pop     ebp
0x10003691 retn
```

## snprintf varargs wrapper: cdecl(dst,count,format,...), EAX int, caller cleanup

```asm
0x10003620 push    ebp
0x10003621 mov     ebp, esp
0x10003623 lea     eax, [ebp+ArgList]
0x10003626 push    eax; ArgList
0x10003627 push    0; Locale
0x10003629 push    [ebp+Format]; Format
0x1000362c push    [ebp+BufferCount]; BufferCount
0x1000362f push    [ebp+Buffer]; Buffer
0x10003632 call    sub_10003610
0x10003637 mov     ecx, [eax]
0x10003639 push    dword ptr [eax+4]
0x1000363c or      ecx, 1
0x1000363f push    ecx; Options
0x10003640 call    ds:__stdio_common_vsprintf
0x10003646 or      ecx, 0FFFFFFFFh
0x10003649 add     esp, 1Ch
0x1000364c test    eax, eax
0x1000364e cmovs   eax, ecx
0x10003651 pop     ebp
0x10003652 retn
```

## GetProfileForName caller: full raw cvar name → sanitizer → LegacyKey; ECX=Career

```asm
0x1000f279 mov     eax, dword_100C30C0
0x1000f27e push    offset aName; "name"
0x1000f283 mov     eax, [eax+40h]
0x1000f286 call    eax
0x1000f288 mov     edi, eax
0x1000f28a push    edi; Source
0x1000f28b call    sub_1001A110
0x1000f290 mov     ecx, dword_100C206C
0x1000f296 add     esp, 8
0x1000f299 push    eax
0x1000f29a call    sub_10019E10
0x1000f29f mov     esi, eax
0x1000f2a1 mov     [ebp+Block], esi
0x1000f2a7 test    edi, edi
```

## DeleteProfile caller: ECX=Career, selected raw name pointer on stack

```asm
0x1001c351 cmp     [ebx+1F8h], al
0x1001c357 lea     edi, [ebx+1F8h]
0x1001c35d jz      short loc_1001C37A
0x1001c35f mov     ecx, dword_100C206C
0x1001c365 push    edi; Source
0x1001c366 call    sub_10019DA0
0x1001c36b mov     ecx, ebx; int
0x1001c36d mov     byte ptr [edi], 0
0x1001c370 call    sub_1001C940
0x1001c375 jmp     loc_1001C543
```
