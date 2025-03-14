#include <android/log.h>
#include <android/dlext.h>
#include <sys/system_properties.h>
#include <android/asset_manager.h>
#include <dlfcn.h>
#include <unistd.h>
#include <cstdlib>
#include <thread>
#include <ranges>
#include "zygisk.hpp"
#include "cJSON.h"
#include "shadowhook.h"

#define TARGET_LIB "libdexprotectorx.so"
#define LOG_TAG "ZygiskHook"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==== Hook ====
typedef void (*T_Callback)(void *, const char *, const char *, uint32_t);
static T_Callback o_callback = nullptr;
static void (*orig_system_property_read_callback)(prop_info *, T_Callback, void *) = nullptr;
static void modify_callback(void *cookie, const char *name, const char *value, uint32_t serial) {
    if (!cookie || !name || !value || !o_callback) return;

    const char *oldValue = value;

    std::string_view prop(name);

    LOGE("modify_callback[%s]: %s", name, oldValue);
    return o_callback(cookie, name, value, serial);
}
static void my_system_property_read_callback(prop_info *pi, T_Callback callback, void *cookie) {
    if (pi && callback && cookie) o_callback = callback;
    return orig_system_property_read_callback(pi, modify_callback, cookie);
}
static bool hook_system_property_read_callback() {
    if (shadowhook_hook_sym_name(nullptr, "__system_property_read_callback", (void *) my_system_property_read_callback, (void **) &orig_system_property_read_callback) != NULL) {
        LOGE("hook __system_property_read_callback successful");
        return true;
    }
    LOGE("hook __system_property_read_callback failed!");
    return false;
}

void *(*orig_lib_func)(void *a1, void *a2, int a3);
void *my_lib_func(void *a1, void *a2, int a3) {
    void* ret = orig_lib_func(a1, a2, a3);
    LOGE("lib_func: %s", (char *)ret);
    return ret;
}

void *(*orig_open_2)(const char *file, int oflag);
void *my_open_2(const char *file, int oflag) {
    LOGE("open_2: %s %d", file, oflag);
    return orig_open_2(file, oflag);
}

void *(*orig_kill)(pid_t pid, int sig);
void *my_kill(pid_t pid, int sig) {
    LOGE("kill: %d flags: %d", pid, sig);
    return orig_kill(pid, sig);
}

static unsigned long libso_base_addr = 0;
static void* libso_handle = nullptr;

void *(*orig_dlopen)(const char *filename, int flags);
void *my_dlopen(const char *filename, int flags) {
    LOGE("dlopen: %s flags: %08x", filename, flags);

    void* handle = orig_dlopen(filename, flags);
    /*
    if(!libso_handle){
        if(strstr(filename, TARGET_LIB)){
            libso_handle = handle;
            LOGE("libso handle %lx", (long)libso_handle);

            void *exportedFunc = DobbySymbolResolver(TARGET_LIB, "JNI_OnLoad");
            if (exportedFunc != nullptr) {
                LOGE("libso exported func addr %lx", exportedFunc);
            }

            if (NULL != shadowhook_hook_sym_name((void *)((unsigned long)exportedFunc+93208), (void *) my_lib_func, (void **) &orig_lib_func)) {
                LOGE("libso hooked func addr %lx", (unsigned long)exportedFunc+93208);
            }

            sleep(5);
        }
    }
    // */
    return handle;
}

void *(*orig_dlsym)(void *handle, const char *name);
void *my_dlsym(void *handle, const char *name) {
    LOGE("dlsym: %s", name);
    return orig_dlsym(handle, name);
}

AAsset* (*orig_AAssetManager_open)(AAssetManager* mgr, const char* filename, int mode) = nullptr;
AAsset* my_AAssetManager_open(AAssetManager* mgr, const char* filename, int mode) {
    // LOGE("AAssetManager_open: %s %d", filename, mode);
    AAsset* asset = orig_AAssetManager_open(mgr, filename, mode);
    return asset;
}

void *(*orig_android_dlopen_ext)(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info);
void *my_android_dlopen_ext(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info) {
    LOGE("android_dlopen_ext: %s flags: %08x", __filename, __flags);

    void* handle = orig_android_dlopen_ext(__filename, __flags, __info);
    // /*
    if(!libso_handle){
        if(strstr(__filename, TARGET_LIB)){
            libso_handle = handle;
            LOGE("libso handle %lx", (long)libso_handle);

            void *exportedFunc = dlsym(handle, "JNI_OnLoad");
            if (exportedFunc != nullptr) {
                LOGE("libso exported func addr %lx", exportedFunc);
            }

            if (NULL != shadowhook_hook_sym_addr((void *)((unsigned long)exportedFunc+93208), (void *) my_lib_func, (void **) &orig_lib_func)) {
                LOGE("libso hooked func addr %lx", (unsigned long)exportedFunc+93208);
            }

            sleep(5);
        }
    }
    // */
    return handle;
}


class ZygiskHook : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!args) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        auto nice_name = env->GetStringUTFChars(args->nice_name, nullptr);

        if (!nice_name) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }


        bool doHook = false;
        std::string config_file = "/data/local/tmp/zygisk.hook/" + nice_name + ".txt";

        if (std::filesystem::exists(config_file)) {
            doHook = true;
        }
    
        env->ReleaseStringUTFChars(args->nice_name, nice_name);

        if (!doHook) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);

        app_name = nice_name;
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (app_name.empty()) return;

        LOGE("====================\n\ndo hook %s", app_name.c_str());
        shadowhook_hook_sym_name(nullptr, "kill", (void *) my_kill, (void **) &orig_kill);
        shadowhook_hook_sym_name(nullptr, "dlopen", (void *) my_dlopen, (void **) &orig_dlopen);
        shadowhook_hook_sym_name(nullptr, "dlsym", (void *) my_dlsym, (void **) &orig_dlsym);
        shadowhook_hook_sym_name(nullptr, "android_dlopen_ext", (void *) my_android_dlopen_ext, (void **) &orig_android_dlopen_ext);
        shadowhook_hook_sym_name("libandroid.so", "AAssetManager_open", (void *) my_AAssetManager_open, (void **) &orig_AAssetManager_open);
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    std::string app_name;
};

REGISTER_ZYGISK_MODULE(ZygiskHook)