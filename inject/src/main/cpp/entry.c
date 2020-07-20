#include <stdio.h>
#include <unistd.h>
#include <android/log.h>
#define LOG_TAG "inject"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

int hook_entry(const char * a){
    LOGD("Hook success, pid = %d\n", getpid());
    LOGD("Hello %s\n", a);
    return 0;
}
