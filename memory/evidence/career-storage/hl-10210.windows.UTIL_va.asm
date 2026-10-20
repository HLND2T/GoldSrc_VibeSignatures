; Binary bound in hl-10210.windows.json; returned UTIL_va result, cdecl varargs

bin/hl-10210/gameui/GameUI.dll:     file format pei-i386


Disassembly of section .text:

10034f30 <.text+0x33f30>:
10034f30:	55                   	push   ebp
10034f31:	8b ec                	mov    ebp,esp
10034f33:	a1 78 59 0c 10       	mov    eax,ds:0x100c5978
10034f38:	40                   	inc    eax
10034f39:	25 03 00 00 80       	and    eax,0x80000003
10034f3e:	79 05                	jns    0x10034f45
10034f40:	48                   	dec    eax
10034f41:	83 c8 fc             	or     eax,0xfffffffc
10034f44:	40                   	inc    eax
10034f45:	8d 4d 0c             	lea    ecx,[ebp+0xc]
10034f48:	a3 78 59 0c 10       	mov    ds:0x100c5978,eax
10034f4d:	51                   	push   ecx
10034f4e:	6a 00                	push   0x0
10034f50:	ff 75 08             	push   DWORD PTR [ebp+0x8]
10034f53:	c1 e0 0a             	shl    eax,0xa
10034f56:	05 78 49 0c 10       	add    eax,0x100c4978
10034f5b:	68 00 04 00 00       	push   0x400
10034f60:	50                   	push   eax
10034f61:	e8 aa e6 fc ff       	call   0x10003610
10034f66:	8b 08                	mov    ecx,DWORD PTR [eax]
10034f68:	ff 70 04             	push   DWORD PTR [eax+0x4]
10034f6b:	83 c9 01             	or     ecx,0x1
10034f6e:	51                   	push   ecx
10034f6f:	ff 15 90 01 09 10    	call   DWORD PTR ds:0x10090190
10034f75:	a1 78 59 0c 10       	mov    eax,ds:0x100c5978
10034f7a:	83 c4 1c             	add    esp,0x1c
10034f7d:	c1 e0 0a             	shl    eax,0xa
10034f80:	05 78 49 0c 10       	add    eax,0x100c4978
10034f85:	5d                   	pop    ebp
10034f86:	c3                   	ret
