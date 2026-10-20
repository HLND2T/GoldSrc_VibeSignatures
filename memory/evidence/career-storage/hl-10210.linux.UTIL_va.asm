; Binary bound in hl-10210.linux.json; returned UTIL_va result, cdecl varargs

bin/hl-10210/gameui/gameui.so:     file format elf32-i386


Disassembly of section .text:

000a8040 <_Z7UTIL_vaPcz>:
   a8040:	83 ec 2c             	sub    esp,0x2c
   a8043:	b9 01 00 00 00       	mov    ecx,0x1
   a8048:	a1 a0 c6 19 00       	mov    eax,ds:0x19c6a0
   a804d:	89 4c 24 08          	mov    DWORD PTR [esp+0x8],ecx
   a8051:	40                   	inc    eax
   a8052:	99                   	cdq
   a8053:	c1 ea 1e             	shr    edx,0x1e
   a8056:	01 d0                	add    eax,edx
   a8058:	83 e0 03             	and    eax,0x3
   a805b:	29 d0                	sub    eax,edx
   a805d:	8d 54 24 34          	lea    edx,[esp+0x34]
   a8061:	89 54 24 14          	mov    DWORD PTR [esp+0x14],edx
   a8065:	8b 54 24 30          	mov    edx,DWORD PTR [esp+0x30]
   a8069:	a3 a0 c6 19 00       	mov    ds:0x19c6a0,eax
   a806e:	c1 e0 0a             	shl    eax,0xa
   a8071:	05 a0 b6 19 00       	add    eax,0x19b6a0
   a8076:	89 04 24             	mov    DWORD PTR [esp],eax
   a8079:	89 54 24 10          	mov    DWORD PTR [esp+0x10],edx
   a807d:	ba ff ff ff ff       	mov    edx,0xffffffff
   a8082:	89 54 24 0c          	mov    DWORD PTR [esp+0xc],edx
   a8086:	ba 00 04 00 00       	mov    edx,0x400
   a808b:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
   a808f:	e8 fc ff ff ff       	call   a8090 <_Z7UTIL_vaPcz+0x50>
   a8094:	a1 a0 c6 19 00       	mov    eax,ds:0x19c6a0
   a8099:	83 c4 2c             	add    esp,0x2c
   a809c:	c1 e0 0a             	shl    eax,0xa
   a809f:	05 a0 b6 19 00       	add    eax,0x19b6a0
   a80a4:	c3                   	ret
