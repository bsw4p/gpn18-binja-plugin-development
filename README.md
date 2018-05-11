# gpn18-binja-plugin-development
Slides from my talk at the Gulasch Programming Night 18 about developing Binary Ninja plugins. The idea was to supply everything that is needed to quickly get started with writing new plugins. Recording at: https://www.youtube.com/watch?v=L2xYV9WLVoE (Sorry german only for now. I initially wanted to give the talk in english but didn't feel well enough in the end. Might redo it again in englich soonish. Also sorry for the bad prepared example section at the end).

<!-- $theme: default -->
<!-- footer: Benedikt Schmotzle -- Binary Ninja Plugin Development -- GPN18 -->

Binary Ninja Plugin Development
===

--- 

# Binary Ninja

https://binary.ninja/

* Cross platform reversing: Linux, OSX, Windows
* Supported architectures: X86/ARM/MIPS/...
* Intermediate Languages (low, medium, ...)
* GUI / (headless)
* cheaper than IDA :)
* nice Python API

---

# API

https://api.binary.ninja/

https://github.com/Vector35/binaryninja-api

https://github.com/Vector35/community-plugins/tree/master/plugins

---

# Plugin paths

* Windows
	* %APPDATA%/Binary Ninja/plugins
* Linux
	* $HOME/.binaryninja/plugins
* OSX
	* ~/Library/Application Support/Binary Ninja/plugins
---

# Better debugging using EPDB 

## Linux

From BinaryNinja shell
```bash
import pip; pip.main(['install', 'epdb']); 
import epdb; epdb.serve()
```

From Python shell
```python
import epdb; epdb.connect()
```

## Windows

working on porting epdb

---


# API Basics

```python
here # get address at cursor

print(hex(here)) # print address in hex
```

---

# Binary Views

```python
bv = BinaryViewType['ELF'].open("/bin/ls")
```

---

# Sections

```python
bv.sections.keys()
# ['.dynstr', '.text', ...]

bv.sections['.text']
# <section .text: 0x402a00-0x413c59>

bv.sections['.text'].start
# 4205056L

bv.sections['.text'].end
# 4275289L
```
---

# Symbols

```python
bv.symbols
# {...'puts@GOT': <SymbolType.ImportAddressSymbol: 
#            "puts@GOT" @ 0x804a010>, ... }

bv.get_symbol_at(0x804a010)
# <SymbolType.ImportAddressSymbol: "puts@GOT" @ 0x804a010>

bv.get_symbol_by_raw_name('puts')
# <SymbolType.ImportedFunctionSymbol: "puts" @ 0x8048330>
```

---

# Architecture

```python
bv.arch 
# <arch: x86_64>

bv.arch.endianness 
# <Endianness.LittleEndian: 0>

bv.arch.address_size 
# 8L
bv.arch.calling_conventions
# { 'win64': <calling convention: x86_64 win64>, 
#   'sysv': <calling convention: x86_64 sysv>, 
#'linux-syscall': <calling convention: x86_64 linux-syscall>}

bv.arch.calling_conventions['sysv'].int_arg_regs
# ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

bv.arch.calling_conventions['sysv'].int_return_reg
# 'rax'
```

---

# (Dis)assembling

```python
bv.get_disassembly(t.start)
# 'push    r15'

bv.arch.assemble("push r15")
# ('AW', ''))

```

---

# Functions

```python
bv.functions
# [<func: x86_64@0x4022b8>, ..., <func: x86_64@0x413c5c>]

# Get function at address
bv.get_functions_containing(0x413871)[0]
# <func: x86_64@0x413b9c>

bv.functions[0].name
# "_init"

bv.functions[0].vars
# [<var void var_8>, ...]

bv.functions[0].basic_blocks
# [<block: x86_64@0x4022b8-0x4022c8>, ... ]
```
---


# Making comments

```python
f0 = bv.functions[0]

# set_comment_at(address, comment)
f0.set_comment_at(f.start, "beginning of function")

f0.comments
# {4203192L: 'beginning of function'}
```
---

# Basic blocks

```python
b2 = f0.basic_blocks[2]

b2.outgoing_edges
# [<UnconditionalBranch: x86_64@0x4022cd>]

b2.incoming_edges
# [<FalseBranch: x86_64@0x4022c8>]

b2.set_user_highlight(
	HighlightStandardColor.BlueHighlightColor)
```



---

# Instructions

```python
bb.disassembly_text
# [<0x406d60: sub_406d60:>, 
# <0x406d60: push    r15 {var_8}>, 
# ...]

bb.disassembly_text[1].tokens
# ['push', '    ', 'r15', ' {', 'var_8', '}']

f0.set_user_instr_highlight(f0.start, 
    highlight.HighlightColor(red=0xff, blue=0xff, green=0))
```

---

# Binary Ninja Intermediate Languages

* Human readable
* Computer understandable (SSA)
* Easy to lift
* Easy to translate

---

# Low level Intermediate Language (LLIL)

https://docs.binary.ninja/dev/bnil-llil/

* Close to asm
* Eliminate side effects
* Eliminate nops

---
```
0   0x4005c7    push rbp
1   0x4005c8    mov rbp, rsp
2   0x4005cb    sub rsp, 0x20
3   0x4005cf    mov dword [rbp-0x14], edi
4   0x4005d2    mov qword [rbp-0x20], rsi
5   0x4005d6    rax = [rbp - 0x20 {var_28}].q
6   0x4005da    mov rdi, rax
7   0x4005dd    call atoi
8   0x4005e2    mov dword [rbp-0x4], eax
...
```

```
0   0x4005c7    push(rbp)
1   0x4005c8    rbp = rsp {__saved_rbp}
2   0x4005cb    rsp = rsp - 0x20
3   0x4005cf    [rbp - 0x14 {var_1c}].d = edi
4   0x4005d2    [rbp - 0x20 {var_28}].q = rsi
5   0x4005d6    rax = [rbp - 0x20 {var_28}].q
6   0x4005da    rdi = rax
7   0x4005dd    call(atoi) ## 0x4004a0
8   0x4005e2    [rbp - 4 {var_c}].d = eax
...
```
---


```python
f1.get_regs_written_by(f1.low_level_il[7].address)
# ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 
# 'r11', 'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 
# 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 
# 'xmm13', 'xmm14', 'xmm15']
```

---

# Working with LLIL

```python
f1.low_level_il[2]
# <il: r14d = r8d>

f1.low_level_il[2].operation
# <LowLevelILOperation.LLIL_SET_REG: 1>
```

---

# LLIL Operands

```python
f1.low_level_il[2].operands
# [r14d, <il: r8d>]

f1.low_level_il[2].operands[0].info
# <reg: size 4, offset 0 in r14, zero extend>

f1.low_level_il[2].operands[1].operation
# <LowLevelILOperation.LLIL_REG: 10>

f1.low_level_il[2].operands[1].possible_values
# <unsigned ranges: [<range: 0x0 to 0xffffffff>]>

bv.arch.get_low_level_il_from_bytes("\x90\x90", 0x0)
# <il: nop>
```

---

Some LLIL instruction types..

Name | Description
------------ | -------------
LLIL_CALL | Call to function
LLIL_CMP_E, LLIL_CMP_NE	 | (non) Equality comparison
LLIL_CMP_SGE | Signed greater or equal comparison
LLIL_CMP_UGT | Unsigned greater than comparison	
LLIL_SET_REG | LLIL register assignment
LLIL_PUSH | LLIL push to stack
LLIL_POP | LLIL pop from stack

Full list at: https://api.binary.ninja/binaryninja.enums.LowLevelILOperation.html?highlight=lowleveliloperation

--- 

# Medium level Intermediate Language (MLIL) 

Stack usage resolved
Types added

```python
f1.medium_level_il[3]
# <il: if (rax.eax == 0) then 4 @ 0x8fd else 5 @ 0x8e5>

f1.medium_level_il[0].dest.type
#<type: int32_t, 0% confidence>
```

---

MLIL instruction mostly equal to LLIL

Name | Description
------------ | -------------
MLIL_IF | if condition
MLIL_SYSCALL | syscall instruction


Full list at: https://api.binary.ninja/binaryninja.enums-module.html?highlight=mlil#binaryninja.enums.MediumLevelILOperation

--- 

---


# Crossreferences

```python
# Get address of strcpy
a = bv.get_symbols_by_name("strcpy")[0].address

# Search xrefs
bv.get_code_refs(a)
# [<ref: x86_64@0x406e51>, ...]

# Map xref to function
r1 = bv.get_code_refs(a)[0]
bv.get_functions_containing(r1.address)[0].name
# sub_406d60

```

---

# Background tasks

```python
class DoSomethingAs(BackgroundTaskThread):
      def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.progress = "Doing something..."
        self.view = view
        
      def doSomething():
        ...
```

---

## plugin.json

```json

{
	"plugin": {
		"name": "msdn",
		"type": ["ui"],
		"api": "python2",
		"description": "Search MSDN api reference",
		"longdescription": "...",
		"license": {
			"name": "MIT"
		},
		"version": "0.0.1",
		"author": "Benedikt Schmotzle"
	}
}
```

---

## __init__.py

```python
from binaryninja import *

def search_and_render(bv):
	...

def search_and_render_addr(bv, address):
	...

# register plugin
PluginCommand.register("Search MSDN", 
"Searches the MSDN Api and ...",
search_and_render)

PluginCommand.register_for_address(
'Search MSDN from instruction', 
'Search MSDN for call from instruction', 
search_and_render_addr)
```

---

## UI

```python

c = ChoiceField('Do it?', ['Yes', 'No'])
a = AddressField('Enter address')
get_form_input([c, a], "Window title")

print(c.result)
print(a.result)

```

```python
show_message_box(
 "BoxTitle", 
 "BoxMessage"
)
```

---

# Other fields

https://api.binary.ninja/binaryninja.interaction-module.html

Name |
------------ | 
DirectoryNameField | 
IntegerField | 
OpenFileNameField | 
LineField | 
MultilineField | 
SaveFileNameField | 

---



---

# Example: Dangerous functions plugin (aka Hello World)

--- 

# Further reading

https://binary.ninja/2017/04/17/BNIL-Series-Part-1.html
https://www.sophia.re/Binary-Rockstar/index.html
https://blog.trailofbits.com/2018/04/04/vulnerability-modeling-with-binary-ninja/

---


# Questions?

---

# Thank you

---
