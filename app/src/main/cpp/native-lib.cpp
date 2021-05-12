#include <jni.h>
#include <string>
#include <map>
#include <vector>
#include <stdio.h>
#include <unistd.h>

#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>

#include <nghttp2/nghttp2.h>
#include <mbedtls/debug.h>

#include "CurlWrapper.h"

#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "MainActivityJNI", __VA_ARGS__))

std::string android_tempdir(JNIEnv *env, jobject obj) {
    jclass activityClass = env->FindClass("android/app/NativeActivity");
    jmethodID getCacheDir = env->GetMethodID(activityClass, "getCacheDir", "()Ljava/io/File;");
    jobject cache_dir = env->CallObjectMethod(obj, getCacheDir);

    jclass fileClass = env->FindClass("java/io/File");
    jmethodID getPath = env->GetMethodID(fileClass, "getPath", "()Ljava/lang/String;");
    jstring path_string = (jstring)env->CallObjectMethod(cache_dir, getPath);
    const char *path_chars = env->GetStringUTFChars(path_string, NULL);
    std::string result{path_chars};
    env->ReleaseStringUTFChars(path_string, path_chars);

    return result;
}

jobject getAssetManagerFromJava(JNIEnv* env, jobject obj) {
    // All seem to give 0x71
    //jclass clazz = env->FindClass("com/example/curly/MainActivity");
    jclass clazz = env->GetObjectClass(obj);
    if (!clazz) {
        throw std::runtime_error("Can't GetObjectClass");
    }
    jmethodID method =
            env->GetMethodID(clazz, "getAssetManager", "()Landroid/content/res/AssetManager;");
    if (!method) {
        throw std::runtime_error("Can't GetMethodID");
    }
    return env->CallObjectMethod(obj, method);
}

void logAssetDir(AAssetManager *am, std::string name) {
    AAssetDir *ad = AAssetManager_openDir(am, name.c_str());
    if (!ad) {
        LOGD("Can't AAssetManager_openDir %s", name.c_str());
        return;
    }
    while (const char *an = AAssetDir_getNextFileName(ad)) {
        LOGD("%s", an);
    }
    AAssetDir_close(ad);
}

std::string assetPath(JNIEnv *env, jobject obj, std::string name) {
    jobject jam = getAssetManagerFromJava(env, obj);
    if (!jam) {
        throw std::runtime_error("Can't getAssetManagerFromJava");
    }
    AAssetManager* am = AAssetManager_fromJava(env, jam);
    if (!am) {
        throw std::runtime_error("Can't AAssetManager_fromJava");
    }

    logAssetDir(am, "");

    AAsset* assetFile = AAssetManager_open(am, name.c_str(), AASSET_MODE_BUFFER);
    if (!assetFile) {
        throw std::runtime_error("Can't AAssetManager_open");
    }
    const void* buf = AAsset_getBuffer(assetFile);
    off_t len = AAsset_getLength(assetFile);
    AAsset_close(assetFile);

    std::string tmppath = android_tempdir(env, obj) + "/" + name + ".XXXXXX";
    char *tmplate = strdup(tmppath.c_str());
    int fd = mkstemp(tmplate);
    if (fd < 0) {
        LOGD("mkstemp(%s) returned %d errno %d", tmppath.c_str(), fd, errno);
        throw std::runtime_error("Can't mkstemp");
    }
    if (write(fd, buf, len) != len) {
        throw std::runtime_error("Can't write");
    }
    close(fd);
    std::string result{tmplate};
    delete [] tmplate;
    return result;
}

static inline void ltrim(std::string &s) {
    s.erase(s.begin(), find_if(s.begin(), s.end(), [](int ch) {
        return !isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(find_if(s.rbegin(), s.rend(), [](int ch) {
        return !isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

static double parseCurlHTTPVersion(long version) {
    switch (version) {
        case CURL_HTTP_VERSION_1_0: return 1.0;
        case CURL_HTTP_VERSION_1_1: return 1.1;
        case CURL_HTTP_VERSION_2_0: return 2.0;
            // TODO: Documented for 7.50+, but does not exist in 7.68, so what happens
            //       if we later enable HTTP/3? No idea.
            // case CURL_HTTP_VERSION_3: return 3.0;
        default: return 0;
    }
}

std::string fetch(std::string url) {

    struct UserData {
        std::exception_ptr ep;
        std::stringstream ss;
        bool firstLine = true; // see NOTE below in header callback
        bool connected = false;
        std::map<std::string, std::string> headers;
        std::string statusMessage;
    };
    UserData userData;

    mbedtls_debug_set_threshold(4);

    CurlGlobals &globals = CurlGlobals::Get();

    CurlHandle curl;

    char curlErrorBuffer[CURL_ERROR_SIZE];
    curl.setopt(CURLOPT_ERRORBUFFER, curlErrorBuffer);

    curl.setopt(CURLOPT_SHARE, globals.share);

    // https://curl.haxx.se/libcurl/c/threadsafe.html
    curl.setopt(CURLOPT_NOSIGNAL, 1);

    curl.setopt(CURLOPT_VERBOSE, 1); // turn on for verbose logging
    struct ScopeExitFlushStderr {
        ~ScopeExitFlushStderr() { fflush(stderr); }
    } flushStderrForCurloptVerbose;

    // TODO: Setting TFO unconditionally may or may not be the best option. On
    //       Android, as long as you can count on Android 4.4+, it's at least
    //       safe, and shouldn't hurt performance; not sure about iOS, macOS,
    //       Windows, etc.
    curl.setopt(CURLOPT_TCP_FASTOPEN, 1);

    // Accept whatever encodings have been compiled into libcurl (which should
    // be at least deflate and gzip, maybe also br).
    curl.setopt(CURLOPT_ACCEPT_ENCODING, "");

    // There's no way to tell whether an http server supports HTTP/2 except by
    // trying and failing and then making an HTTP/1.1 connection instead.
    // However, an https server, you can discover as part of the post-TLS
    // CONNECT negotiation. So, curl offers an option to try HTTP/2 on https
    // connections, but not bother on http connections. This is probably what
    // we want (our appspot game servers want https and support HTTP/2; our
    // dcon servers cannot support https and may or may not support HTTP/2).
    curl.setopt(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);

    if (url.substr(0, 5) == "https") {
        if (globals.usecabundle) {
            curl.setopt(CURLOPT_CAINFO, globals.capath);
            curl.setopt(CURLOPT_CAPATH, nullptr);
        } else if (globals.usecadirectory) {
            curl.setopt(CURLOPT_CAPATH, globals.capath);
            curl.setopt(CURLOPT_CAINFO, nullptr);
        } else {
            // curl.setopt(CURLOPT_SSL_VERIFYPEER, 0); // HACK HACK HACK: disable root CA verification. Also change Initialize if you want to allow this.
            throw std::runtime_error("Attempting to use HTTPS without CA store available");
        }
    }

    curl.setopt(CURLOPT_URL, url);

    auto hcb = [](char *contents, size_t size, size_t nmemb, void *userp) -> size_t {
        assert(size == 1);
        assert(nmemb);
        UserData *c = static_cast<UserData *>(userp);
        if (!c->connected) { c->connected = true; }
        size_t len = size * nmemb;
        std::string str(contents, len);
        trim(str);
        // NOTE: curl will call us back once for the status line, for each header line, and
        //       for the blank line between headers and body--but if there are multiple responses
        //       (e.g., after a 100 continue or a 30x redirect) it will do that for all of them.
        //       So, when we see a blank line, either that means we'll never be called again, or
        //       that when we are called again it's starting a new response. So if we are called
        //       again, throw out the previous status and header (unless you want to stash a
        //       chain of all redirects, which some libraries do, but we don't care).
        if (str.empty()) {
            c->firstLine = true;
        } else {
            if (c->firstLine) {
                c->firstLine = false;
                c->headers.clear();
                // An HTTP status line consists of an HTTP version, whitespace, a status code,
                // then optional whitespace and arbitrary text (which may include whitespace) as
                // a status message. Curl will already parse the version and code for us, but it
                // doesn't extract the remainder and stash it anywhere, it just gives us the same
                // line it already parsed, so we have to parse it.
                std::stringstream ss(str);
                std::string token;
                ss >> token >> token;
                getline(ss, token);
                trim(token);
                c->statusMessage = token;
            } else {
                // After the status line, every following line (after dealing with obsolete
                // continuation-line folding, which curl already does for us) until the blank
                // is a header. Technically it must be field-name ":" OWS field-value OWS,
                // but practically, some implementations do weird things like illegal whitespace
                // before the colon, or no colon when the value is blank, so this is the safe
                // thing to do.
                auto pos = str.find(':');
                if (pos != str.npos) {
                    std::string name = str.substr(0, pos);
                    trim(name);
                    std::string value = str.substr(pos + 1);
                    trim(value);
                    c->headers[name] = value;
                } else {
                    c->headers[str] = "";
                }
            }
        }
        return size * nmemb;
    };
    curl.setopt(CURLOPT_HEADERFUNCTION, static_cast<CURL_WRITEFUNCTION_T>(hcb));
    curl.setopt(CURLOPT_HEADERDATA, &userData);

    auto cb = [](char *contents, size_t size, size_t nmemb, void *userp) -> size_t {
        UserData *c = static_cast<UserData *>(userp);
        // NOTE: This (receiving a body callback without any header
        // callbacks first) can only happen for HTTP/0.9.
        if (!c->connected) { c->connected = true; }
        try {
            c->ss.write(contents, size * nmemb);
            return size * nmemb;
        } catch (std::exception &e) {
            c->ep = std::current_exception();
            return 0;
        }
    };
    curl.setopt(CURLOPT_WRITEFUNCTION, static_cast<CURL_WRITEFUNCTION_T>(cb));
    curl.setopt(CURLOPT_WRITEDATA, &userData);

    CURLcode res = curl_easy_perform(curl.handle);
    if (userData.ep) {
        // TODO: can we combine this with the CurlError if any instead of ignoring?
        //       (usually it will just be CURLE_ABORTED_BY_CALLBACK)
        std::rethrow_exception(userData.ep);
    }
    if (res != CURLE_OK) {
        CurlCheck(res, curl.info_long(CURLINFO_OS_ERRNO), curlErrorBuffer);
    }

    LOGD("effective url: %s", curl.info_string(CURLINFO_EFFECTIVE_URL).c_str());
    LOGD("http version: %f", parseCurlHTTPVersion(curl.info_long(CURLINFO_HTTP_VERSION)));
    LOGD("status code: %d", (int)curl.info_long(CURLINFO_RESPONSE_CODE));
    LOGD("status message: %s", userData.statusMessage.c_str());
    LOGD("headers:");
    for (auto pair: userData.headers) {
        LOGD("  %s: %s", pair.first.c_str(), pair.second.c_str());
    }
    LOGD("---");
    LOGD("%s", userData.ss.str().c_str());

    return userData.ss.str();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_curly_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject obj) {
    nghttp2_info *nginfo = nghttp2_version(0);
    LOGD("%s", nginfo->version_str);

    try {
        std::string path = assetPath(env, obj, "cacerts.pem");

        CurlGlobals::globals.reset(new CurlGlobals(path));

        std::string s = fetch("https://example.com");

        return env->NewStringUTF(s.c_str());
    } catch (const std::exception &e) {
        return env->NewStringUTF(e.what());
    }
}
