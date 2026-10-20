; hl-10210 Linux; bound to SHA-256 in hl-10210.linux.json
0x62b80 push    ebp
0x62b81 push    edi
0x62b82 push    esi
0x62b83 push    ebx
0x62b84 sub     esp, 3Ch
0x62b87 mov     ebx, [this_0+0ACh]
0x62b8d test    ebx, ebx
0x62b8f jz      loc_62C5E
0x62b95 mov     edi, ctWins
0x62b97 or      edi, tWins
0x62b99 mov     [esp+4Ch+var_20], edi
0x62b9d jnz     loc_62C77
0x62ba3 mov     ebp, [ebx+58h]
0x62ba6 mov     tWins, this_0
0x62ba8 mov     [esp+4Ch+this], this_0
0x62bac mov     this_0, [ebx+54h]
0x62baf mov     edi, ebp
0x62bb1 sub     edi, eax
0x62bb3 sar     edi, 2
0x62bb6 test    edi, edi
0x62bb8 jle     loc_62C88
0x62bbe mov     bl, 1
0x62bc0 xor     esi, esi
0x62bc2 mov     byte ptr [esp+4Ch+tasksCompleted], bl
0x62bc6 mov     ebx, this_0
0x62bc8 nop
0x62bc9 lea     i, [i+0]
0x62bd0 cmp     ebp, eax
0x62bd2 jz      short loc_62BF7
0x62bd4 mov     ecx, [eax]
0x62bd6 xor     edx, edx
0x62bd8 add     eax, 4
0x62bdb test    i, i
0x62bdd jnz     short loc_62BF2
0x62bdf jmp     short loc_62C10
0x62be8 add     eax, 4
0x62beb cmp     edx, i
0x62bed mov     ecx, [eax-4]
0x62bf0 jz      short loc_62C10
0x62bf2 inc     edx
0x62bf3 cmp     ebp, eax
0x62bf5 jnz     short loc_62BE8
0x62bf7 inc     i
0x62bf8 cmp     edi, esi
0x62bfa mov     byte ptr [esp+4Ch+tasksCompleted], 0
0x62bff jz      short loc_62C2C
0x62c01 mov     edx, [this_0+0ACh]
0x62c07 mov     eax, [edx+54h]
0x62c0a mov     ebp, [edx+58h]
0x62c0d jmp     short loc_62BD0
0x62c10 test    ecx, ecx
0x62c12 jz      short loc_62BF7
0x62c14 mov     eax, [ecx]
0x62c16 mov     eax, [eax]
0x62c18 cmp     eax, offset _ZN13CCareerUITask10IsCompleteEv; CCareerUITask::IsComplete(void)
0x62c1d jnz     short loc_62C70
0x62c1f movzx   eax, byte ptr [ecx+4]
0x62c23 test    al, al
0x62c25 jz      short loc_62BF7
0x62c27 inc     i
0x62c28 cmp     edi, i
0x62c2a jnz     short loc_62C01
0x62c2c movzx   this_0, byte ptr [esp+4Ch+tasksCompleted]
0x62c31 test    bl, bl
0x62c33 jnz     short loc_62C88
0x62c35 mov     eax, [esp+4Ch+this]
0x62c39 mov     esi, 1
0x62c3e mov     dword ptr [esp+4Ch+updateConfig], esi; updateConfig
0x62c42 mov     [esp+4Ch+var_4C], eax; this
0x62c45 call    _ZN11CCareerGame11SaveProfileEb; CCareerGame::SaveProfile(bool)
0x62c4a mov     ebx, [esp+4Ch+var_20]
0x62c4e test    ebx, ebx
0x62c50 jz      loc_62D90
0x62c56 mov     eax, [esp+4Ch+this]
0x62c5a mov     byte ptr [eax+42h], 0
0x62c5e add     esp, 3Ch
0x62c61 pop     ebx
0x62c62 pop     esi
0x62c63 pop     edi
0x62c64 pop     ebp
0x62c65 retn
0x62c70 mov     [esp+4Ch+var_4C], ecx
0x62c73 call    eax
0x62c75 jmp     short loc_62C23
0x62c77 mov     [this_0+0FCh], ctWins
0x62c7d mov     [this_0+100h], tWins
0x62c83 jmp     loc_62BA3
0x62c88 mov     eax, [esp+4Ch+this]
0x62c8c mov     esi, [eax+0C0h]
0x62c92 test    esi, esi
0x62c94 jnz     loc_62E10
0x62c9a mov     edi, eax
0x62c9c mov     eax, [eax+100h]
0x62ca2 mov     ecx, [edi+0FCh]
0x62ca8 mov     edx, eax
0x62caa sub     edx, ecx
0x62cac cmp     edx, [edi+0D0h]
0x62cb2 jl      short loc_62C35
0x62cb4 cmp     eax, [edi+0CCh]
0x62cba jl      loc_62C35
0x62cc0 mov     eax, [edi]
0x62cc2 mov     esi, [edi+0ACh]
0x62cc8 mov     eax, [eax+1Ch]
0x62ccb cmp     eax, offset _ZN11CCareerGame16DoesWinUnlockAllEv; CCareerGame::DoesWinUnlockAll(void)
0x62cd0 jnz     loc_63176
0x62cd6 mov     eax, edi
0x62cd8 mov     edi, [edi+5Ch]
0x62cdb mov     ebp, [eax+60h]
0x62cde mov     [esp+4Ch+var_28], edi
0x62ce2 cmp     edi, ebp
0x62ce4 jz      loc_62E3F
0x62cea mov     eax, edi
0x62cec xor     edi, edi
0x62cee jmp     short loc_62D2E
0x62cf0 movzx   ebx, byte ptr [ecx+44h]
0x62cf4 xor     ecx, ecx
0x62cf6 mov     byte ptr [esp+4Ch+tasksCompleted], bl
0x62cfa mov     ebx, [edx+4]
0x62cfd cmp     pNextMap, ebx
0x62cff jz      short loc_62D44
0x62d01 cmp     byte ptr [ebx+44h], 0
0x62d05 jnz     short loc_62D0C
0x62d07 mov     byte ptr [esp+4Ch+tasksCompleted], 0
0x62d0c mov     edx, [edx+8]
0x62d0f cmp     pNextMap, edx
0x62d11 jz      short loc_62D4D
0x62d13 cmp     byte ptr [edx+44h], 0
0x62d17 jnz     short loc_62D1E
0x62d19 mov     byte ptr [esp+4Ch+tasksCompleted], 0
0x62d1e test    cl, cl
0x62d20 jnz     short loc_62D4D
0x62d22 add     eax, 0Ch
0x62d25 inc     edi
0x62d26 cmp     ebp, eax
0x62d28 jz      loc_62E3F
0x62d2e mov     edx, [eax]
0x62d30 mov     ecx, [edx]
0x62d32 cmp     pNextMap, ecx
0x62d34 jnz     short loc_62CF0
0x62d36 mov     ebx, [edx+4]
0x62d39 mov     cl, 1
0x62d3b mov     byte ptr [esp+4Ch+tasksCompleted], 1
0x62d40 cmp     pNextMap, ebx
0x62d42 jnz     short loc_62D01
0x62d44 mov     edx, [edx+8]
0x62d47 mov     cl, 1
0x62d49 cmp     pNextMap, edx
0x62d4b jnz     short loc_62D13
0x62d4d cmp     byte ptr [esp+4Ch+tasksCompleted], 0
0x62d52 mov     eax, pNextMap
0x62d54 jz      loc_62E41
0x62d5a mov     ebx, [esp+4Ch+this]
0x62d5e cmp     byte ptr [ebx+41h], 0
0x62d62 jnz     loc_62E41
0x62d68 mov     pNextMap, ebp
0x62d6a mov     ebp, [esp+4Ch+var_28]
0x62d6e sub     eax, ebp
0x62d70 sar     eax, 2
0x62d73 imul    eax, 0AAAAAAABh
0x62d79 dec     eax
0x62d7a cmp     edi, eax
0x62d7c mov     eax, pNextMap
0x62d7e jnz     loc_62E41
0x62d84 mov     edi, ebx
0x62d86 jmp     loc_63191
0x62d90 mov     edi, [esp+4Ch+this]
0x62d94 mov     eax, ds:engine
0x62d99 mov     byte ptr [edi+68h], 0
0x62d9d call    dword ptr [eax+200h]
0x62da3 mov     ecx, [edi+0E8h]
0x62da9 mov     edx, [edi+0E4h]
0x62daf mov     eax, ecx
0x62db1 sub     eax, edx
0x62db3 shr     eax, 2
0x62db6 jz      short loc_62DF9
0x62db8 xor     ebx, ebx
0x62dba lea     esi, [esi+0]
0x62dc0 mov     esi, [edx+i*4]
0x62dc3 test    esi, esi
0x62dc5 jz      short loc_62DE3
0x62dc7 mov     [esp+4Ch+var_4C], esi; this
0x62dca call    _ZN9CvarLatchD1Ev; CvarLatch::~CvarLatch()
0x62dcf mov     [esp+4Ch+var_4C], esi; void *
0x62dd2 call    _ZdlPv; operator delete(void *)
0x62dd7 mov     ecx, [edi+0E8h]
0x62ddd mov     edx, [edi+0E4h]
0x62de3 mov     eax, ecx
0x62de5 inc     i
0x62de6 sub     eax, edx
0x62de8 sar     eax, 2
0x62deb cmp     eax, i
0x62ded ja      short loc_62DC0
0x62def mov     eax, [esp+4Ch+this]
0x62df3 mov     [eax+0E8h], edx
0x62df9 mov     eax, ds:engine
0x62dfe mov     [esp+4Ch+var_4C], offset aExecConfigCfg; "exec config.cfg\n"
0x62e05 call    dword ptr [eax+50h]
0x62e08 add     esp, 3Ch
0x62e0b pop     ebx
0x62e0c pop     esi
0x62e0d pop     edi
0x62e0e pop     ebp
0x62e0f retn
0x62e10 mov     edi, eax
0x62e12 mov     eax, [eax+0FCh]
0x62e18 mov     ebx, [edi+100h]
0x62e1e mov     edx, eax
0x62e20 sub     edx, ebx
0x62e22 cmp     edx, [edi+0D0h]
0x62e28 jl      loc_62C35
0x62e2e cmp     eax, [edi+0CCh]
0x62e34 jl      loc_62C35
0x62e3a jmp     loc_62CC0
0x62e3f mov     eax, pNextMap
0x62e41 test    eax, eax
0x62e43 mov     edi, [esp+4Ch+this]
0x62e47 jz      loc_62EDB
0x62e4d cmp     byte ptr [eax+44h], 0
0x62e51 jnz     loc_62EDB
0x62e57 inc     dword ptr [edi+0Ch]
0x62e5a mov     byte ptr [eax+44h], 1
0x62e5e mov     eax, [edi+5Ch]
0x62e61 mov     edi, [edi+60h]
0x62e64 cmp     eax, edi
0x62e66 mov     [esp+4Ch+var_28], edi
0x62e6a jz      short loc_62ECF
0x62e6c mov     edx, [eax]
0x62e6e mov     edi, [edx]
0x62e70 cmp     byte ptr [edi+44h], 0
0x62e74 jz      loc_630D0
0x62e7a mov     edi, [edx+4]
0x62e7d cmp     byte ptr [edi+44h], 0
0x62e81 jz      loc_630D0
0x62e87 mov     edi, [edx+8]
0x62e8a lea     edx, [eax+0Ch]
0x62e8d mov     ebx, [esp+4Ch+var_28]
0x62e91 cmp     byte ptr [edi+44h], 0
0x62e95 jnz     short loc_62ECB
0x62e97 jmp     loc_630D0
0x62ea0 mov     ecx, [edx]
0x62ea2 mov     edi, [ecx]
0x62ea4 cmp     byte ptr [edi+44h], 0
0x62ea8 jz      loc_630D0
0x62eae mov     edi, [ecx+4]
0x62eb1 cmp     byte ptr [edi+44h], 0
0x62eb5 jz      loc_630D0
0x62ebb mov     edi, [ecx+8]
0x62ebe add     edx, 0Ch
0x62ec1 cmp     byte ptr [edi+44h], 0
0x62ec5 jz      loc_630D0
0x62ecb cmp     ebx, edx
0x62ecd jnz     short loc_62EA0
0x62ecf mov     edi, [esp+4Ch+this]
0x62ed3 mov     edi, [edi+0ACh]
0x62ed9 jmp     short loc_62EE7
0x62edb mov     eax, [edi+5Ch]
0x62ede mov     edi, [edi+60h]
0x62ee1 mov     [esp+4Ch+var_28], edi
0x62ee5 mov     edi, pNextMap
0x62ee7 mov     ebx, [esp+4Ch+this]
0x62eeb add     pNextMap, 4
0x62eee cmp     [esp+4Ch+var_28], eax
0x62ef2 mov     byte ptr [ebx+69h], 0
0x62ef6 jz      loc_62F89
0x62efc mov     [esp+4Ch+tasksCompleted], eax
0x62f00 mov     [esp+4Ch+pCurrentMap], pCurrentMap_0
0x62f04 jmp     short loc_62F23
0x62f10 test    bl, bl
0x62f12 jz      short loc_62F85
0x62f14 add     [esp+4Ch+tasksCompleted], 0Ch
0x62f19 mov     eax, [esp+4Ch+tasksCompleted]
0x62f1d cmp     [esp+4Ch+var_28], eax
0x62f21 jz      short loc_62F85
0x62f23 mov     ebp, [eax]
0x62f25 mov     ebx, [ebp+0]
0x62f28 mov     [esp+4Ch+var_4C], edi; s1
0x62f2b lea     eax, [ebx+4]
0x62f2e mov     dword ptr [esp+4Ch+updateConfig], eax; s2
0x62f32 call    strcasecmp
0x62f37 test    eax, eax
0x62f39 jz      loc_63166
0x62f3f mov     esi, [ebp+4]
0x62f42 movzx   ebx, byte ptr [ebx+44h]
0x62f46 mov     [esp+4Ch+var_4C], edi; s1
0x62f49 lea     eax, [esi+4]
0x62f4c mov     dword ptr [esp+4Ch+updateConfig], eax; s2
0x62f50 call    strcasecmp
0x62f55 test    eax, eax
0x62f57 jz      loc_63126
0x62f5d cmp     byte ptr [esi+44h], 0
0x62f61 jnz     short loc_62F65
0x62f63 xor     ebx, ebx
0x62f65 mov     esi, [ebp+8]
0x62f68 mov     [esp+4Ch+var_4C], edi; s1
0x62f6b lea     eax, [esi+4]
0x62f6e mov     dword ptr [esp+4Ch+updateConfig], eax; s2
0x62f72 call    strcasecmp
0x62f77 test    eax, eax
0x62f79 jz      loc_6316E
0x62f7f cmp     byte ptr [esi+44h], 0
0x62f83 jnz     short loc_62F10
0x62f85 mov     esi, [esp+4Ch+pCurrentMap]
0x62f89 mov     eax, [esp+4Ch+this]
0x62f8d xor     ecx, ecx
0x62f8f mov     [eax+0ACh], ecx
0x62f95 mov     ebx, [esi+54h]
0x62f98 cmp     ebx, [esi+58h]
0x62f9b jnz     short loc_62FB8
0x62f9d jmp     short loc_62FD4
0x62fa0 xor     ebp, ebp
0x62fa2 add     ebx, 4
0x62fa5 mov     byte ptr [eax+5], 0
0x62fa9 mov     byte ptr [eax+4], 0
0x62fad mov     [eax+1110h], ebp
0x62fb3 cmp     [esi+58h], ebx
0x62fb6 jz      short loc_62FD4
0x62fb8 mov     eax, [ebx]
0x62fba mov     edx, [eax]
0x62fbc mov     edx, [edx+1Ch]
0x62fbf cmp     edx, offset _ZN13CCareerUITask5ResetEv; CCareerUITask::Reset(void)
0x62fc5 jz      short loc_62FA0
0x62fc7 mov     [esp+4Ch+var_4C], eax
0x62fca add     ebx, 4
0x62fcd call    edx
0x62fcf cmp     [esi+58h], ebx
0x62fd2 jnz     short loc_62FB8
0x62fd4 mov     eax, 1
0x62fd9 mov     dword ptr [esp+4Ch+updateConfig], eax; updateConfig
0x62fdd mov     eax, [esp+4Ch+this]
0x62fe1 mov     [esp+4Ch+var_4C], eax; this
0x62fe4 call    _ZN11CCareerGame11SaveProfileEb; CCareerGame::SaveProfile(bool)
0x62fe9 mov     ebx, [esi+54h]
0x62fec cmp     it, [esi+58h]
0x62fef jnz     short loc_63010
0x62ff1 jmp     short loc_63032
0x62ff8 xor     edi, edi
0x62ffa add     it, 4
0x62ffd mov     byte ptr [task+5], 1
0x63001 mov     byte ptr [task+4], 1
0x63005 mov     [task+1110h], edi
0x6300b cmp     [esi+58h], it
0x6300e jz      short loc_63032
0x63010 mov     eax, [it]
0x63012 mov     edx, [task]
0x63014 mov     edx, [edx+20h]
0x63017 cmp     edx, offset _ZN13CCareerUITask3SetEb; CCareerUITask::Set(bool)
0x6301d jz      short loc_62FF8
0x6301f xor     ecx, ecx
0x63021 add     it, 4
0x63024 mov     dword ptr [esp+4Ch+updateConfig], ecx
0x63028 mov     [esp+4Ch+var_4C], task
0x6302b call    edx
0x6302d cmp     [esi+58h], it
0x63030 jnz     short loc_63010
0x63032 mov     eax, [esp+4Ch+this]
0x63036 add     esi, 4
0x63039 mov     edi, [eax+60h]
0x6303c mov     byte ptr [eax+69h], 0
0x63040 mov     it, edi
0x63042 mov     [esp+4Ch+var_28], edi
0x63046 mov     edi, [eax+5Ch]
0x63049 cmp     edi, ebx
0x6304b jnz     short loc_6305D
0x6304d jmp     short loc_630BF
0x63050 test    bl, bl
0x63052 jz      short loc_630BF
0x63054 add     edi, 0Ch
0x63057 cmp     [esp+4Ch+var_28], edi
0x6305b jz      short loc_630BF
0x6305d mov     ebp, [edi]
0x6305f mov     ebx, [ebp+0]
0x63062 mov     [esp+4Ch+var_4C], esi; s1
0x63065 lea     eax, [ebx+4]
0x63068 mov     dword ptr [esp+4Ch+updateConfig], eax; s2
0x6306c call    strcasecmp
0x63071 test    eax, eax
0x63073 jz      loc_63122
0x63079 mov     edx, [ebp+4]
0x6307c movzx   ebx, byte ptr [ebx+44h]
0x63080 mov     [esp+4Ch+var_4C], esi; s1
0x63083 lea     eax, [edx+4]
0x63086 mov     dword ptr [esp+4Ch+updateConfig], eax; s2
0x6308a mov     [esp+4Ch+tasksCompleted], edx
0x6308e call    strcasecmp
0x63093 mov     edx, [esp+4Ch+tasksCompleted]
0x63097 test    eax, eax
0x63099 jz      short loc_630E8
0x6309b cmp     byte ptr [edx+44h], 0
0x6309f jnz     short loc_630A3
0x630a1 xor     ebx, ebx
0x630a3 mov     ebp, [ebp+8]
0x630a6 mov     [esp+4Ch+var_4C], esi; s1
0x630a9 lea     eax, [ebp+4]
0x630ac mov     dword ptr [esp+4Ch+updateConfig], eax; s2
0x630b0 call    strcasecmp
0x630b5 test    eax, eax
0x630b7 jz      short loc_630EA
0x630b9 cmp     byte ptr [ebp+44h], 0
0x630bd jnz     short loc_63050
0x630bf mov     eax, [esp+4Ch+this]
0x630c3 xor     edx, edx
0x630c5 mov     [eax+0ACh], edx
0x630cb jmp     loc_62C4A
0x630d0 test    edi, edi
0x630d2 jz      loc_62ECF
0x630d8 mov     ebx, [esp+4Ch+this]
0x630dc add     pNextMap, 4
0x630df mov     byte ptr [ebx+69h], 0
0x630e3 jmp     loc_62EFC
0x630e8 mov     ebp, edx
0x630ea mov     edi, [esp+4Ch+this]
0x630ee test    ebp, ebp
0x630f0 mov     eax, edi
0x630f2 mov     [edi+0ACh], ebp
0x630f8 jz      loc_62C4A
0x630fe add     eax, 69h ; 'i'
0x63101 mov     ebp, 40h ; '@'
0x63106 mov     [esp+4Ch+n], ebp; n
0x6310a mov     dword ptr [esp+4Ch+updateConfig], esi; src
0x6310e mov     [esp+4Ch+var_4C], eax; dest
0x63111 call    strncpy
0x63116 mov     byte ptr [edi+0A8h], 0
0x6311d jmp     loc_62C4A
0x63122 mov     ebp, ebx
0x63124 jmp     short loc_630EA
0x63126 mov     edx, esi
0x63128 mov     esi, [esp+4Ch+pCurrentMap]
0x6312c mov     ebp, edx
0x6312e mov     eax, [esp+4Ch+this]
0x63132 test    ebp, ebp
0x63134 mov     [eax+0ACh], ebp
0x6313a jz      loc_62F95
0x63140 mov     edx, 40h ; '@'
0x63145 mov     dword ptr [esp+4Ch+updateConfig], edi; src
0x63149 mov     edi, eax
0x6314b add     eax, 69h ; 'i'
0x6314e mov     [esp+4Ch+n], edx; n
0x63152 mov     [esp+4Ch+var_4C], eax; dest
0x63155 call    strncpy
0x6315a mov     byte ptr [edi+0A8h], 0
0x63161 jmp     loc_62F95
0x63166 mov     esi, [esp+4Ch+pCurrentMap]
0x6316a mov     ebp, ebx
0x6316c jmp     short loc_6312E
0x6316e mov     ebp, esi
0x63170 mov     esi, [esp+4Ch+pCurrentMap]
0x63174 jmp     short loc_6312E
0x63176 mov     [esp+4Ch+var_4C], edi
0x63179 call    eax
0x6317b test    al, al
0x6317d mov     eax, [esp+4Ch+this]
0x63181 mov     eax, [eax+0ACh]
0x63187 jz      loc_62E41
0x6318d mov     edi, [esp+4Ch+this]
0x63191 mov     edx, [edi+0F0h]
0x63197 mov     cl, 1
0x63199 mov     [edi+edx+0F4h], cl
0x631a0 jmp     loc_62E41
