; hl-10210 Linux; bound to SHA-256 in hl-10210.linux.json
0x6e170 push    ebp
0x6e171 push    edi
0x6e172 mov     edi, this
0x6e174 push    esi
0x6e175 push    ebx
0x6e176 sub     esp, 3Ch
0x6e179 mov     [esp+4Ch+savedData], savedData_0
0x6e17d mov     ebx, [esp+4Ch+save]
0x6e181 mov     [esp+4Ch+dataLength], dataLength_0
0x6e185 call    _Z9READ_LONGv; READ_LONG(void)
0x6e18a mov     esi, eax
0x6e18c dec     version
0x6e18d cmp     eax, 3
0x6e190 jbe     short loc_6E1A0
0x6e192 add     esp, 3Ch
0x6e195 xor     eax, eax
0x6e197 pop     ebx
0x6e198 pop     esi
0x6e199 pop     edi
0x6e19a pop     ebp
0x6e19b retn
0x6e1a0 call    _Z11READ_STRINGv; READ_STRING(void)
0x6e1a5 mov     [esp+4Ch+s], computedChecksum; s
0x6e1a8 mov     ebp, computedChecksum
0x6e1aa call    strlen
0x6e1af mov     [esp+4Ch+var_48], ebp; char *
0x6e1b3 mov     [esp+4Ch+var_44], computedChecksum; unsigned int
0x6e1b7 lea     computedChecksum, [ebx+4]
0x6e1ba mov     [esp+4Ch+s], computedChecksum; this
0x6e1bd call    _ZNSs6assignEPKcj; std::string::assign(char const*,uint)
0x6e1c2 call    _Z9READ_LONGv; READ_LONG(void)
0x6e1c7 cmp     version, 4
0x6e1ca mov     [ebx+8], computedChecksum
0x6e1cd jz      short loc_6E200
0x6e1cf mov     dword ptr [ebx+0Ch], 0
0x6e1d6 call    _Z7READ_OKv; READ_OK(void)
0x6e1db test    computedChecksum, computedChecksum
0x6e1dd jnz     short loc_6E210
0x6e1df call    _Z9READ_LONGv; READ_LONG(void)
0x6e1e4 mov     this, [esp+4Ch+dataLength]
0x6e1e8 sub     edi, 4
0x6e1eb test    edi, edi
0x6e1ed jle     short loc_6E192
0x6e1ef mov     [esp+4Ch+checksum], computedChecksum
0x6e1f3 mov     [esp+4Ch+isSaveOk], 0
0x6e1f8 jmp     loc_6E33E
0x6e200 call    _Z9READ_BYTEv; READ_BYTE(void)
0x6e205 cmp     computedChecksum, 3
0x6e208 mov     [ebx+0Ch], computedChecksum
0x6e20b jbe     short loc_6E1D6
0x6e20d jmp     short loc_6E1CF
0x6e210 xor     edx, edx
0x6e212 mov     ebp, edx
0x6e214 call    _Z9READ_BYTEv; READ_BYTE(void)
0x6e219 test    computedChecksum, computedChecksum
0x6e21b setnz   byte ptr [ebx+ebp+10h]
0x6e220 inc     ebp
0x6e221 cmp     ebp, 4
0x6e224 jnz     short loc_6E214
0x6e226 call    _Z7READ_OKv; READ_OK(void)
0x6e22b test    computedChecksum, computedChecksum
0x6e22d jz      short loc_6E1DF
0x6e22f lea     computedChecksum, [ebx+14h]
0x6e232 mov     [esp+4Ch+var_44], version; version
0x6e236 mov     [esp+4Ch+var_48], computedChecksum; save
0x6e23a mov     [esp+4Ch+s], this; this
0x6e23d call    _ZN11CCareerGame20ParseDifficultyChunkEP28CCareerProfileDifficultyDatai; CCareerGame::ParseDifficultyChunk(CCareerProfileDifficultyData *,int)
0x6e242 test    al, al
0x6e244 jz      short loc_6E1DF
0x6e246 lea     computedChecksum, [ebx+3Ch]
0x6e249 mov     [esp+4Ch+var_44], version; version
0x6e24d mov     [esp+4Ch+var_48], computedChecksum; save
0x6e251 mov     [esp+4Ch+s], this; this
0x6e254 call    _ZN11CCareerGame20ParseDifficultyChunkEP28CCareerProfileDifficultyDatai; CCareerGame::ParseDifficultyChunk(CCareerProfileDifficultyData *,int)
0x6e259 test    al, al
0x6e25b jz      short loc_6E1DF
0x6e25d lea     computedChecksum, [ebx+64h]
0x6e260 mov     [esp+4Ch+var_44], version; version
0x6e264 mov     [esp+4Ch+var_48], computedChecksum; save
0x6e268 mov     [esp+4Ch+s], this; this
0x6e26b call    _ZN11CCareerGame20ParseDifficultyChunkEP28CCareerProfileDifficultyDatai; CCareerGame::ParseDifficultyChunk(CCareerProfileDifficultyData *,int)
0x6e270 test    al, al
0x6e272 mov     [esp+4Ch+isSaveOk], al
0x6e276 jz      loc_6E1DF
0x6e27c lea     computedChecksum, [ebx+8Ch]
0x6e282 mov     [esp+4Ch+var_44], version; version
0x6e286 mov     [esp+4Ch+var_48], computedChecksum; save
0x6e28a mov     [esp+4Ch+s], this; this
0x6e28d call    _ZN11CCareerGame20ParseDifficultyChunkEP28CCareerProfileDifficultyDatai; CCareerGame::ParseDifficultyChunk(CCareerProfileDifficultyData *,int)
0x6e292 test    ebx, ebx
0x6e294 setz    dl
0x6e297 cmp     al, dl
0x6e299 jbe     loc_6E1DF
0x6e29f lea     computedChecksum, [ebx+0B4h]
0x6e2a5 mov     ecx, 400h
0x6e2aa test    al, 1
0x6e2ac jnz     loc_6E65A
0x6e2b2 test    al, 2
0x6e2b4 jnz     loc_6E64A
0x6e2ba mov     this, ecx
0x6e2bc xor     edx, edx
0x6e2be and     edi, 0FFFFFFF8h
0x6e2c1 xor     ebp, ebp
0x6e2c3 mov     dword ptr [computedChecksum+edx], 0
0x6e2ca mov     [computedChecksum+edx+4], ebp
0x6e2ce add     edx, 8
0x6e2d1 cmp     edx, edi
0x6e2d3 jb      short loc_6E2C1
0x6e2d5 add     computedChecksum, edx
0x6e2d7 test    cl, 4
0x6e2da jz      short loc_6E2E5
0x6e2dc mov     dword ptr [computedChecksum], 0
0x6e2e2 add     computedChecksum, 4
0x6e2e5 test    cl, 2
0x6e2e8 jz      short loc_6E2F2
0x6e2ea mov     word ptr [computedChecksum], 0
0x6e2ef add     computedChecksum, 2
0x6e2f2 test    cl, 1
0x6e2f5 jz      short loc_6E2FA
0x6e2f7 mov     byte ptr [computedChecksum], 0
0x6e2fa dec     version
0x6e2fb jz      short loc_6E326
0x6e2fd call    _Z9READ_LONGv; READ_LONG(void)
0x6e302 test    computedChecksum, computedChecksum
0x6e304 mov     esi, computedChecksum
0x6e306 jle     short loc_6E326
0x6e308 xor     edi, edi
0x6e30a lea     esi, [esi+0]
0x6e310 call    _Z9READ_LONGv; READ_LONG(void)
0x6e315 cmp     edi, 0FFh
0x6e31b jle     loc_6E694
0x6e321 inc     edi
0x6e322 cmp     esi, edi
0x6e324 jnz     short loc_6E310
0x6e326 call    _Z9READ_LONGv; READ_LONG(void)
0x6e32b mov     edi, [esp+4Ch+dataLength]
0x6e32f sub     edi, 4
0x6e332 test    edi, edi
0x6e334 mov     [esp+4Ch+checksum], computedChecksum
0x6e338 jle     loc_6E690
0x6e33e mov     esi, [esp+4Ch+savedData]
0x6e342 test    edi, edi
0x6e344 mov     computedChecksum, 1
0x6e349 cmovg   computedChecksum, edi
0x6e34c mov     [esp+4Ch+dataLength], computedChecksum
0x6e350 neg     esi
0x6e352 and     esi, 0Fh
0x6e355 cmp     esi, computedChecksum
0x6e357 cmova   esi, computedChecksum
0x6e35a cmp     computedChecksum, 12h
0x6e35d jg      loc_6E678
0x6e363 mov     esi, computedChecksum
0x6e365 mov     edx, [esp+4Ch+savedData]
0x6e369 lea     ebp, [esi+1]
0x6e36c xor     computedChecksum, computedChecksum
0x6e36e mov     ecx, 1
0x6e373 lea     esi, [esi+0]
0x6e379 lea     edi, [edi+0]
0x6e380 movzx   ebx, byte ptr [edx]
0x6e383 inc     edx
0x6e384 imul    ebx, ecx
0x6e387 inc     ecx
0x6e388 add     computedChecksum, ebx
0x6e38a cmp     ecx, ebp
0x6e38c jnz     short loc_6E380
0x6e38e cmp     esi, [esp+4Ch+dataLength]
0x6e392 jz      loc_6E630
0x6e398 mov     ebx, [esp+4Ch+dataLength]
0x6e39c sub     ebx, esi
0x6e39e lea     ecx, [ebx-10h]
0x6e3a1 shr     ecx, 4
0x6e3a4 mov     [esp+4Ch+var_28], ebx
0x6e3a8 lea     ebx, [ecx+1]
0x6e3ab mov     [esp+4Ch+var_24], ebx
0x6e3af shl     ebx, 4
0x6e3b2 test    edi, edi
0x6e3b4 mov     [esp+4Ch+dataLength], ebx
0x6e3b8 lea     ecx, [edi-1]
0x6e3bb mov     ebx, 0
0x6e3c0 cmovle  ecx, ebx
0x6e3c3 sub     ecx, esi
0x6e3c5 cmp     ecx, 0Eh
0x6e3c8 jbe     loc_6E530
0x6e3ce mov     ecx, [esp+4Ch+savedData]
0x6e3d2 movd    xmm6, ebp
0x6e3d6 pshufd  xmm4, xmm6, 0
0x6e3db mov     ebx, [esp+4Ch+dataLength]
0x6e3df pxor    xmm0, xmm0
0x6e3e3 pxor    xmm7, xmm7
0x6e3e7 paddd   xmm4, ds:xmmword_13EA30
0x6e3ef add     esi, ecx
0x6e3f1 xor     ecx, ecx
0x6e3f3 movdqa  xmm1, xmmword ptr [esi]
0x6e3f7 pxor    xmm6, xmm6
0x6e3fb movdqa  xmm2, xmm1
0x6e3ff punpckhbw xmm1, xmm6
0x6e403 punpcklbw xmm2, xmm6
0x6e407 movdqa  xmm6, xmm4
0x6e40b movdqa  xmm5, xmm2
0x6e40f psrlq   xmm6, 20h ; ' '
0x6e414 punpcklwd xmm5, xmm7
0x6e418 movdqa  xmm3, xmm5
0x6e41c psrlq   xmm5, 20h ; ' '
0x6e421 pmuludq xmm3, xmm4
0x6e425 pmuludq xmm5, xmm6
0x6e429 pshufd  xmm3, xmm3, 8
0x6e42e punpckhwd xmm2, xmm7
0x6e432 pshufd  xmm5, xmm5, 8
0x6e437 punpckldq xmm3, xmm5
0x6e43b movdqa  xmm5, ds:xmmword_13EA50
0x6e443 paddd   xmm5, xmm4
0x6e447 paddd   xmm0, xmm3
0x6e44b movdqa  xmm3, xmm5
0x6e44f psrlq   xmm5, 20h ; ' '
0x6e454 pmuludq xmm3, xmm2
0x6e458 psrlq   xmm2, 20h ; ' '
0x6e45d pshufd  xmm3, xmm3, 8
0x6e462 inc     ecx
0x6e463 pmuludq xmm2, xmm5
0x6e467 movdqa  xmm5, ds:xmmword_13EA60
0x6e46f paddd   xmm5, xmm4
0x6e473 pshufd  xmm2, xmm2, 8
0x6e478 punpckldq xmm3, xmm2
0x6e47c movdqa  xmm2, xmm1
0x6e480 paddd   xmm0, xmm3
0x6e484 punpcklwd xmm2, xmm7
0x6e488 movdqa  xmm3, xmm5
0x6e48c psrlq   xmm5, 20h ; ' '
0x6e491 pmuludq xmm3, xmm2
0x6e495 punpckhwd xmm1, xmm7
0x6e499 psrlq   xmm2, 20h ; ' '
0x6e49e pshufd  xmm3, xmm3, 8
0x6e4a3 add     esi, 10h
0x6e4a6 pmuludq xmm2, xmm5
0x6e4aa pshufd  xmm2, xmm2, 8
0x6e4af cmp     ecx, [esp+4Ch+var_24]
0x6e4b3 punpckldq xmm3, xmm2
0x6e4b7 paddd   xmm0, xmm3
0x6e4bb movdqa  xmm3, ds:xmmword_13EA70
0x6e4c3 paddd   xmm3, xmm4
0x6e4c7 movdqa  xmm2, xmm3
0x6e4cb psrlq   xmm3, 20h ; ' '
0x6e4d0 pmuludq xmm2, xmm1
0x6e4d4 psrlq   xmm1, 20h ; ' '
0x6e4d9 pshufd  xmm2, xmm2, 8
0x6e4de pmuludq xmm1, xmm3
0x6e4e2 pshufd  xmm1, xmm1, 8
0x6e4e7 paddd   xmm4, ds:xmmword_13EA40
0x6e4ef punpckldq xmm2, xmm1
0x6e4f3 paddd   xmm0, xmm2
0x6e4f7 jb      loc_6E3F3
0x6e4fd movdqa  xmm1, xmm0
0x6e501 psrldq  xmm1, 8
0x6e506 add     ebp, ebx
0x6e508 paddd   xmm0, xmm1
0x6e50c add     edx, ebx
0x6e50e movdqa  xmm1, xmm0
0x6e512 psrldq  xmm1, 4
0x6e517 paddd   xmm0, xmm1
0x6e51b movd    ecx, xmm0
0x6e51f add     computedChecksum, ecx
0x6e521 cmp     [esp+4Ch+var_28], ebx
0x6e525 mov     [esp+4Ch+dataLength], ebx
0x6e529 jz      loc_6E630
0x6e52f nop
0x6e530 movzx   ecx, byte ptr [edx]
0x6e533 imul    ecx, ebp
0x6e536 add     computedChecksum, ecx
0x6e538 lea     ecx, [ebp+1]
0x6e53b cmp     ecx, edi
0x6e53d jg      loc_6E630
0x6e543 movzx   ebx, byte ptr [edx+1]
0x6e547 imul    ecx, ebx
0x6e54a add     computedChecksum, ecx
0x6e54c lea     ecx, [ebp+2]
0x6e54f cmp     edi, ecx
0x6e551 jl      loc_6E630
0x6e557 movzx   ebx, byte ptr [edx+2]
0x6e55b imul    ecx, ebx
0x6e55e add     computedChecksum, ecx
0x6e560 lea     ecx, [ebp+3]
0x6e563 cmp     edi, ecx
0x6e565 jl      loc_6E630
0x6e56b movzx   ebx, byte ptr [edx+3]
0x6e56f imul    ecx, ebx
0x6e572 add     computedChecksum, ecx
0x6e574 lea     ecx, [ebp+4]
0x6e577 cmp     edi, ecx
0x6e579 jl      loc_6E630
0x6e57f movzx   ebx, byte ptr [edx+4]
0x6e583 imul    ecx, ebx
0x6e586 add     computedChecksum, ecx
0x6e588 lea     ecx, [ebp+5]
0x6e58b cmp     edi, ecx
0x6e58d jl      loc_6E630
0x6e593 movzx   ebx, byte ptr [edx+5]
0x6e597 imul    ecx, ebx
0x6e59a add     computedChecksum, ecx
0x6e59c lea     ecx, [ebp+6]
0x6e59f cmp     edi, ecx
0x6e5a1 jl      loc_6E630
0x6e5a7 movzx   ebx, byte ptr [edx+6]
0x6e5ab imul    ecx, ebx
0x6e5ae add     computedChecksum, ecx
0x6e5b0 lea     ecx, [ebp+7]
0x6e5b3 cmp     edi, ecx
0x6e5b5 jl      short loc_6E630
0x6e5b7 movzx   ebx, byte ptr [edx+7]
0x6e5bb imul    ecx, ebx
0x6e5be add     computedChecksum, ecx
0x6e5c0 lea     ecx, [ebp+8]
0x6e5c3 cmp     edi, ecx
0x6e5c5 jl      short loc_6E630
0x6e5c7 movzx   ebx, byte ptr [edx+8]
0x6e5cb imul    ecx, ebx
0x6e5ce add     computedChecksum, ecx
0x6e5d0 lea     ecx, [ebp+9]
0x6e5d3 cmp     edi, ecx
0x6e5d5 jl      short loc_6E630
0x6e5d7 movzx   ebx, byte ptr [edx+9]
0x6e5db imul    ecx, ebx
0x6e5de add     computedChecksum, ecx
0x6e5e0 lea     ecx, [ebp+0Ah]
0x6e5e3 cmp     edi, ecx
0x6e5e5 jl      short loc_6E630
0x6e5e7 movzx   ebx, byte ptr [edx+0Ah]
0x6e5eb imul    ecx, ebx
0x6e5ee add     computedChecksum, ecx
0x6e5f0 lea     ecx, [ebp+0Bh]
0x6e5f3 cmp     edi, ecx
0x6e5f5 jl      short loc_6E630
0x6e5f7 movzx   ebx, byte ptr [edx+0Bh]
0x6e5fb imul    ecx, ebx
0x6e5fe add     computedChecksum, ecx
0x6e600 lea     ecx, [ebp+0Ch]
0x6e603 cmp     edi, ecx
0x6e605 jl      short loc_6E630
0x6e607 movzx   ebx, byte ptr [edx+0Ch]
0x6e60b imul    ecx, ebx
0x6e60e add     computedChecksum, ecx
0x6e610 lea     ecx, [ebp+0Dh]
0x6e613 cmp     edi, ecx
0x6e615 jl      short loc_6E630
0x6e617 movzx   ebx, byte ptr [edx+0Dh]
0x6e61b add     ebp, 0Eh
0x6e61e imul    ecx, ebx
0x6e621 add     computedChecksum, ecx
0x6e623 cmp     edi, ebp
0x6e625 jl      short loc_6E630
0x6e627 movzx   edx, byte ptr [edx+0Eh]
0x6e62b imul    ebp, edx
0x6e62e add     computedChecksum, ebp
0x6e630 cmp     [esp+4Ch+isSaveOk], 0
0x6e635 jz      loc_6E192
0x6e63b cmp     [esp+4Ch+checksum], computedChecksum
0x6e63f setz    al
0x6e642 add     esp, 3Ch
0x6e645 pop     ebx
0x6e646 pop     esi
0x6e647 pop     edi
0x6e648 pop     ebp
0x6e649 retn
0x6e64a mov     word ptr [computedChecksum], 0
0x6e64f sub     ecx, 2
0x6e652 add     computedChecksum, 2
0x6e655 jmp     loc_6E2BA
0x6e65a mov     byte ptr [ebx+0B4h], 0
0x6e661 lea     computedChecksum, [ebx+0B5h]
0x6e667 mov     ecx, 3FFh
0x6e66c jmp     loc_6E2B2
0x6e678 test    esi, esi
0x6e67a jnz     loc_6E365
0x6e680 mov     edx, [esp+4Ch+savedData]
0x6e684 xor     computedChecksum, computedChecksum
0x6e686 mov     ebp, 1
0x6e68b jmp     loc_6E398
0x6e690 xor     computedChecksum, computedChecksum
0x6e692 jmp     short loc_6E63B
0x6e694 mov     [ebx+edi*4+0B4h], computedChecksum
0x6e69b jmp     loc_6E321
