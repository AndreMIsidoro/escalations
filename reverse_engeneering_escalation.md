# Reverse Engeneering Escalation

## 1st Acquire general information

Run the file command on the executable

	file <executable>

Run strings command on the executable

	strings <executable>

	Also try to find encoded strings

	strings -e b <filename>

## Use ltrace

Use ltrace to analyse the library calls:

	ltrace ./<executable> <args>

## Look at the executable code

Using ghidra:

	https://github.com/Andre92Marcos/tools/tree/master/ghidra