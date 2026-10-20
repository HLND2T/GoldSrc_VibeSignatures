; Binary bound in hl-10210.linux.json; EAX path, EDX length reference, EAX result

bin/hl-10210/gameui/gameui.so:     file format elf32-i386


Disassembly of section .text:

0006c750 <_ZL8ReadFilePKcRi>:
   6c750:	57                   	push   edi
   6c751:	89 d7                	mov    edi,edx
   6c753:	56                   	push   esi
   6c754:	be 58 e9 13 00       	mov    esi,0x13e958
   6c759:	53                   	push   ebx
   6c75a:	89 c3                	mov    ebx,eax
   6c75c:	83 ec 10             	sub    esp,0x10
   6c75f:	e8 2c 2b 06 00       	call   cf290 <_ZN5vgui210filesystemEv>
   6c764:	31 c9                	xor    ecx,ecx
   6c766:	8b 10                	mov    edx,DWORD PTR [eax]
   6c768:	89 4c 24 0c          	mov    DWORD PTR [esp+0xc],ecx
   6c76c:	89 74 24 08          	mov    DWORD PTR [esp+0x8],esi
   6c770:	89 5c 24 04          	mov    DWORD PTR [esp+0x4],ebx
   6c774:	89 04 24             	mov    DWORD PTR [esp],eax
   6c777:	ff 52 2c             	call   DWORD PTR [edx+0x2c]
   6c77a:	85 c0                	test   eax,eax
   6c77c:	74 5a                	je     6c7d8 <_ZL8ReadFilePKcRi+0x88>
   6c77e:	89 c3                	mov    ebx,eax
   6c780:	e8 0b 2b 06 00       	call   cf290 <_ZN5vgui210filesystemEv>
   6c785:	8b 10                	mov    edx,DWORD PTR [eax]
   6c787:	89 5c 24 04          	mov    DWORD PTR [esp+0x4],ebx
   6c78b:	89 04 24             	mov    DWORD PTR [esp],eax
   6c78e:	ff 52 3c             	call   DWORD PTR [edx+0x3c]
   6c791:	89 07                	mov    DWORD PTR [edi],eax
   6c793:	89 04 24             	mov    DWORD PTR [esp],eax
   6c796:	e8 fc ff ff ff       	call   6c797 <_ZL8ReadFilePKcRi+0x47>
   6c79b:	89 c6                	mov    esi,eax
   6c79d:	e8 ee 2a 06 00       	call   cf290 <_ZN5vgui210filesystemEv>
   6c7a2:	8b 0f                	mov    ecx,DWORD PTR [edi]
   6c7a4:	8b 10                	mov    edx,DWORD PTR [eax]
   6c7a6:	89 4c 24 08          	mov    DWORD PTR [esp+0x8],ecx
   6c7aa:	89 5c 24 0c          	mov    DWORD PTR [esp+0xc],ebx
   6c7ae:	89 74 24 04          	mov    DWORD PTR [esp+0x4],esi
   6c7b2:	89 04 24             	mov    DWORD PTR [esp],eax
   6c7b5:	ff 52 58             	call   DWORD PTR [edx+0x58]
   6c7b8:	e8 d3 2a 06 00       	call   cf290 <_ZN5vgui210filesystemEv>
   6c7bd:	8b 10                	mov    edx,DWORD PTR [eax]
   6c7bf:	89 04 24             	mov    DWORD PTR [esp],eax
   6c7c2:	89 5c 24 04          	mov    DWORD PTR [esp+0x4],ebx
   6c7c6:	ff 52 30             	call   DWORD PTR [edx+0x30]
   6c7c9:	89 f0                	mov    eax,esi
   6c7cb:	83 c4 10             	add    esp,0x10
   6c7ce:	5b                   	pop    ebx
   6c7cf:	5e                   	pop    esi
   6c7d0:	5f                   	pop    edi
   6c7d1:	c3                   	ret
   6c7d2:	8d b6 00 00 00 00    	lea    esi,[esi+0x0]
   6c7d8:	c7 07 00 00 00 00    	mov    DWORD PTR [edi],0x0
   6c7de:	31 c0                	xor    eax,eax
   6c7e0:	eb e9                	jmp    6c7cb <_ZL8ReadFilePKcRi+0x7b>
