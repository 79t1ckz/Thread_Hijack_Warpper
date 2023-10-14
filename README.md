# Thread_Hijack_Warpper
An example about how to hijack thread to any (normal) functions you want.

# 中文介绍
* 主要用于劫持线程到一个“非汇编编写的”函数中。
* 输入原始线程通用寄存器上下文、函数调用时通用寄存器上下文、参数，然后可以进行劫持
* 需要自行处理各种调用约定
* 函数调用时的上下文中，非易失寄存器的赋值是无效的。
* 不建议递归劫持，次数多了可能爆栈。
* 编译成静态库比较合适，直接排除test_main文件即可。

# Description In English
* It's mainly used to hijack thread to one "not made by asm" function
* Input Original Basic Context, Calling Basic Context, Function Arguments, and then you can start hijack
* need to handle calling convention by yourself
* In Calling Basic Context, callee-preserved regs are invalid.
* It is not recommended to recursively hijack, as it may cause stack overflow after many times.
* complie it to a .lib file will be better
