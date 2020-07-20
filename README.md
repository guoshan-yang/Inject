
使用ndk中的交叉编译工具编译

```
arm-linux-androideabi-gcc -pie -fPIE --sysroot=/Users/ygs/develop_tools/android-ndk-r14b/platforms/android-21/arch-arm inject.c -o inject
```

```
arm-linux-androideabi-gcc -pie -fPIE --sysroot=/Users/ygs/develop_tools/android-ndk-r14b/platforms/android-21/arch-arm entry.c -fPIC -shared -o entry.so
```
