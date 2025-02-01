# NFS - Network File System

## Run nmap scripts

```
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

## Show Available NFS Shares

```
showmount -e 10.129.14.128
```

## Share Mounting

```
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree.
```

## Unmounting

```
sudo umount ./target-NFS
```