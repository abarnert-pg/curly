# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.10.2)

# Declares and names the project.

project("curly")

get_filename_component(PGENGINE_EXTERNALS_DIR "${CMAKE_SOURCE_DIR}/../../../../../dragons3d/Externals/pgengine/Externals" REALPATH)

message(STATUS "ANDROID_ABI: ${ANDROID_ABI}")

if (${ANDROID_ABI} STREQUAL "arm64-v8a")
    SET(PG_PREBUILT_PACKAGE_TARGET "aarch64-linux-android")
elseif (${ANDROID_ABI} STREQUAL "armeabi-v7a")
    SET(PG_PREBUILT_PACKAGE_TARGET "armv7a-linux-androideabi")
else()
    message(FATAL "Cannot use prebuilt libraries for unknown arch on Android")
endif()

set(EXTRA_LIBS "${EXTRA_LIBS}"
        "${PGENGINE_EXTERNALS_DIR}/curl/${PG_PREBUILT_PACKAGE_TARGET}/lib/libcurl.a"
        "${PGENGINE_EXTERNALS_DIR}/mbedtls/${PG_PREBUILT_PACKAGE_TARGET}/lib/libmbedtls.a"
        "${PGENGINE_EXTERNALS_DIR}/mbedtls/${PG_PREBUILT_PACKAGE_TARGET}/lib/libmbedcrypto.a"
        "${PGENGINE_EXTERNALS_DIR}/mbedtls/${PG_PREBUILT_PACKAGE_TARGET}/lib/libmbedx509.a"
        "${PGENGINE_EXTERNALS_DIR}/nghttp2/${PG_PREBUILT_PACKAGE_TARGET}/lib/libnghttp2.a"
        )

set(EXTRA_INCLUDES "${EXTRA_INCLDUES}"
        "${PGENGINE_EXTERNALS_DIR}/mbedtls/${PG_PREBUILT_PACKAGE_TARGET}/include"
        "${PGENGINE_EXTERNALS_DIR}/nghttp2/${PG_PREBUILT_PACKAGE_TARGET}/include"
        "${PGENGINE_EXTERNALS_DIR}/curl/${PG_PREBUILT_PACKAGE_TARGET}/include"
        )

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
             native-lib

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             native-lib.cpp )

target_include_directories(native-lib BEFORE PUBLIC "${EXTRA_INCLUDES}")

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

find_library( # Sets the name of the path variable.
        android-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        android )

find_library( # Sets the name of the path variable.
        z-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        z )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       native-lib

                       ${EXTRA_LIBS}

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib}
                       ${android-lib}
                       ${z-lib})
