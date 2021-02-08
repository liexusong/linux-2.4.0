```cpp
sys_open()
    |
    \---> getname()
    \---> get_unused_fd()
    \---> filp_open()
              |
              \---> open_namei()
                         |
                         \---> path_init()
                         \---> path_walk()
                         \---> lookup_hash()
                         \---> vfs_create()
              \---> dentry_open()
    \---> fd_install()
```
