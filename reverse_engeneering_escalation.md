# Reverse Engeneering Escalation

## 1st Acquire general information

Run the file command on the executable

	file <executable>

Run strings command on the executable

	strings <executable>

	Also try to find encoded strings

	strings -e b <filename>

## 2 - Look at the executable code

Using ghidra:

	https://github.com/Andre92Marcos/reverse_engineering-binary_exploitation/tree/master/ghidra