; Binary bound in hl-8684.linux.json; EAX path, EDX length reference, EAX result

bin/hl-8684/gameui/gameui.so:     file format elf32-i386


Disassembly of section .text:

000bb2d0 <_ZL8ReadFilePKcRi>:
   bb2d0:	83 ec 1c             	sub    esp,0x1c
   bb2d3:	89 5c 24 10          	mov    DWORD PTR [esp+0x10],ebx
   bb2d7:	89 c3                	mov    ebx,eax
   bb2d9:	89 74 24 14          	mov    DWORD PTR [esp+0x14],esi
   bb2dd:	be 0c 79 16 00       	mov    esi,0x16790c
   bb2e2:	89 7c 24 18          	mov    DWORD PTR [esp+0x18],edi
   bb2e6:	89 d7                	mov    edi,edx
   bb2e8:	e8 fc ff ff ff       	call   bb2e9 <_ZL8ReadFilePKcRi+0x19>
   bb2ed:	31 c9                	xor    ecx,ecx
   bb2ef:	8b 10                	mov    edx,DWORD PTR [eax]
   bb2f1:	89 5c 24 04          	mov    DWORD PTR [esp+0x4],ebx
   bb2f5:	89 4c 24 0c          	mov    DWORD PTR [esp+0xc],ecx
   bb2f9:	89 74 24 08          	mov    DWORD PTR [esp+0x8],esi
   bb2fd:	89 04 24             	mov    DWORD PTR [esp],eax
   bb300:	ff 52 2c             	call   DWORD PTR [edx+0x2c]
   bb303:	85 c0                	test   eax,eax
   bb305:	89 c3                	mov    ebx,eax
   bb307:	74 5f                	je     bb368 <_ZL8ReadFilePKcRi+0x98>
   bb309:	e8 fc ff ff ff       	call   bb30a <_ZL8ReadFilePKcRi+0x3a>
   bb30e:	8b 10                	mov    edx,DWORD PTR [eax]
   bb310:	89 5c 24 04          	mov    DWORD PTR [esp+0x4],ebx
   bb314:	89 04 24             	mov    DWORD PTR [esp],eax
   bb317:	ff 52 3c             	call   DWORD PTR [edx+0x3c]
   bb31a:	89 07                	mov    DWORD PTR [edi],eax
   bb31c:	89 04 24             	mov    DWORD PTR [esp],eax
   bb31f:	e8 fc ff ff ff       	call   bb320 <_ZL8ReadFilePKcRi+0x50>
   bb324:	89 c6                	mov    esi,eax
   bb326:	e8 fc ff ff ff       	call   bb327 <_ZL8ReadFilePKcRi+0x57>
   bb32b:	8b 0f                	mov    ecx,DWORD PTR [edi]
   bb32d:	8b 10                	mov    edx,DWORD PTR [eax]
   bb32f:	89 4c 24 08          	mov    DWORD PTR [esp+0x8],ecx
   bb333:	89 5c 24 0c          	mov    DWORD PTR [esp+0xc],ebx
   bb337:	89 74 24 04          	mov    DWORD PTR [esp+0x4],esi
   bb33b:	89 04 24             	mov    DWORD PTR [esp],eax
   bb33e:	ff 52 58             	call   DWORD PTR [edx+0x58]
   bb341:	e8 fc ff ff ff       	call   bb342 <_ZL8ReadFilePKcRi+0x72>
   bb346:	8b 10                	mov    edx,DWORD PTR [eax]
   bb348:	89 5c 24 04          	mov    DWORD PTR [esp+0x4],ebx
   bb34c:	89 04 24             	mov    DWORD PTR [esp],eax
   bb34f:	ff 52 30             	call   DWORD PTR [edx+0x30]
   bb352:	89 f0                	mov    eax,esi
   bb354:	8b 5c 24 10          	mov    ebx,DWORD PTR [esp+0x10]
   bb358:	8b 74 24 14          	mov    esi,DWORD PTR [esp+0x14]
   bb35c:	8b 7c 24 18          	mov    edi,DWORD PTR [esp+0x18]
   bb360:	83 c4 1c             	add    esp,0x1c
   bb363:	c3                   	ret
   bb364:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
   bb368:	c7 07 00 00 00 00    	mov    DWORD PTR [edi],0x0
   bb36e:	31 f6                	xor    esi,esi
   bb370:	eb e0                	jmp    bb352 <_ZL8ReadFilePKcRi+0x82>
