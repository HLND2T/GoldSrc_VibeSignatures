; Binary bound in hl-8684.linux.json; returned UTIL_va result, cdecl varargs

bin/hl-8684/gameui/gameui.so:     file format elf32-i386


Disassembly of section .text:

000ed170 <_Z7UTIL_vaPcz>:
   ed170:	83 ec 1c             	sub    esp,0x1c
   ed173:	a1 00 c3 1b 00       	mov    eax,ds:0x1bc300
   ed178:	40                   	inc    eax
   ed179:	99                   	cdq
   ed17a:	c1 ea 1e             	shr    edx,0x1e
   ed17d:	01 d0                	add    eax,edx
   ed17f:	83 e0 03             	and    eax,0x3
   ed182:	29 d0                	sub    eax,edx
   ed184:	8d 54 24 24          	lea    edx,[esp+0x24]
   ed188:	89 54 24 0c          	mov    DWORD PTR [esp+0xc],edx
   ed18c:	8b 54 24 20          	mov    edx,DWORD PTR [esp+0x20]
   ed190:	a3 00 c3 1b 00       	mov    ds:0x1bc300,eax
   ed195:	c1 e0 0a             	shl    eax,0xa
   ed198:	05 20 c3 1b 00       	add    eax,0x1bc320
   ed19d:	89 04 24             	mov    DWORD PTR [esp],eax
   ed1a0:	89 54 24 08          	mov    DWORD PTR [esp+0x8],edx
   ed1a4:	ba 00 04 00 00       	mov    edx,0x400
   ed1a9:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
   ed1ad:	e8 fc ff ff ff       	call   ed1ae <_Z7UTIL_vaPcz+0x3e>
   ed1b2:	a1 00 c3 1b 00       	mov    eax,ds:0x1bc300
   ed1b7:	83 c4 1c             	add    esp,0x1c
   ed1ba:	c1 e0 0a             	shl    eax,0xa
   ed1bd:	05 20 c3 1b 00       	add    eax,0x1bc320
   ed1c2:	c3                   	ret
