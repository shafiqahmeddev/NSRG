LOCAL_PATH := $(call my-dir)

# Analogous to https://github.com/android/ndk-samples/blob/master/other-builds/ndkbuild/hello-libs/app/Android.mk

# Prebuild dirs.
include $(CLEAR_VARS)
LOCAL_MODULE := oqs
#LOCAL_SRC_FILES := jniLibs/$(TARGET_ARCH_ABI)/liboqs.so
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
     LOCAL_SRC_FILES := jniLibs/armeabi-v7a/liboqs.so
     else ifeq ($(TARGET_ARCH_ABI),arm64-v8a)
     LOCAL_SRC_FILES := jniLibs/arm64-v8a/liboqs.so
     else ifeq ($(TARGET_ARCH_ABI),x86)
     LOCAL_SRC_FILES := jniLibs/x86/liboqs.so
     else ifeq ($(TARGET_ARCH_ABI),x86_64)
     LOCAL_SRC_FILES := jniLibs/x86_64/liboqs.so
     else
     $(error "Unsupported ABI: $(TARGET_ARCH_ABI)")
     endif
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
include $(PREBUILT_SHARED_LIBRARY)

# Create jni wrapper.
include $(CLEAR_VARS)
LOCAL_MODULE     := oqs-jni
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS     += -Wall
LOCAL_SRC_FILES := $(LOCAL_PATH)/jni/handle.c $(LOCAL_PATH)/jni/KEMs.c  $(LOCAL_PATH)/jni/KeyEncapsulation.c  $(LOCAL_PATH)/jni/Rand.c  $(LOCAL_PATH)/jni/Signature.c  $(LOCAL_PATH)/jni/Sigs.c
LOCAL_LDLIBS    := -llog -landroid
LOCAL_SHARED_LIBRARIES := oqs
include $(BUILD_SHARED_LIBRARY)
