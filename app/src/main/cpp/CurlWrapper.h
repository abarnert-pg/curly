//
//  CurlWrapper.h
//  PGEngine
//
//  Created by Andrew Barnert on 3/19/20.
//  Copyright © 2020 Pocket Gems. All rights reserved.
//

#pragma once

#include <algorithm>
#include <sstream>
#include <string>
#include <map>
#include <shared_mutex>
#include <vector>

// Requires curl 7.62+ (for curl_url_* APIs)
#include <curl/curl.h>

#define CURL_USING_MBEDTLS 1

namespace {

    typedef size_t(*CURL_WRITEFUNCTION_T)(char*, size_t, size_t, void*);

    static int https_thread_setup(void) { return 1; }
    static int https_thread_cleanup(void) { return 1; }

    struct CurlBaseError : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    struct CurlError : CurlBaseError {
        CURLcode res = CURLE_OK;
        long errnum = 0; // system errno captured by curl that caused the error, if any
        CurlError() : CurlBaseError("unknown curl error") {}
        CurlError(CURLcode r) : CurlBaseError(curl_easy_strerror(r)), res(r) {}
        CurlError(CURLcode r, long e)
                : CurlBaseError(curl_easy_strerror(r)), res(r), errnum(e) {}
        CurlError(CURLcode r, long e, const char *msg)
                : CurlBaseError(builderr(r, e, msg)), res(r), errnum(e) {}

        static std::string builderr(CURLcode r, long e, const char *msg) {
            std::stringstream ss;
            ss << msg << " : " << curl_easy_strerror(r) << " (" << (int)r << ")";
            if (e) ss << " : " << strerror((int)e) << " (" << e << ")";
            return ss.str();
        }
    };

    struct CurlTimeoutError : CurlError {
        using CurlError::CurlError;
    };

    struct CurlConnectError : CurlError {
        using CurlError::CurlError;
    };

    struct CurlShareError : CurlBaseError {
        CURLSHcode res = CURLSHE_OK;
        CurlShareError() : CurlBaseError("unknown curl share error") {}
        CurlShareError(CURLSHcode r) : CurlBaseError(curl_share_strerror(r)), res(r) {}
    };

    struct CurlUrlError : CurlBaseError {
        CURLUcode res = CURLUE_OK;
        CurlUrlError() : CurlBaseError("unknown curl url error") {}
        // NOTE: There is no curl_url_strerror, unlike the other error groups
        CurlUrlError(CURLUcode r) : CurlBaseError(builderr(r)), res(r) {}
        static std::string builderr(CURLUcode r) {
            std::stringstream ss;
            ss << "curl url error " << (int)r;
            return ss.str();
        }
    };

    void CurlCheck(CURLcode res) {
        switch (res) {
            case CURLE_OK: return;
            case CURLE_OPERATION_TIMEDOUT: throw CurlTimeoutError(res);
            case CURLE_COULDNT_CONNECT: throw CurlConnectError(res);
            default: throw CurlError(res);
        }
    }

    void CurlCheck(CURLcode res, long e, const char *msg) {
        switch (res) {
            case CURLE_OK: return;
            case CURLE_OPERATION_TIMEDOUT: throw CurlTimeoutError(res, e, msg);
            case CURLE_COULDNT_CONNECT: throw CurlConnectError(res, e, msg);
            default: throw CurlError(res, e, msg);
        }
    }

    template <typename T>
    T *CurlCheckCreate(T *t) {
        if (!t) throw CurlError();
        return t;
    }

    void CurlCheckShare(CURLSHcode res) {
        switch (res) {
            case CURLSHE_OK: return;
            default: throw CurlShareError(res);
        }
    }

    void CurlCheckUrl(CURLUcode res) {
        switch (res) {
            case CURLUE_OK: return;
            default: throw CurlUrlError(res);
        }
    }

    struct CurlSList {
        curl_slist *slist;
        CurlSList() : slist(nullptr) {}
        ~CurlSList() { if (slist) curl_slist_free_all(slist); }
        CurlSList(const CurlSList &) = delete;
        CurlSList(CurlSList &&other) : slist(nullptr) { std::swap(slist, other.slist); }
        CurlSList &operator=(const CurlSList &) = delete;
        CurlSList &operator=(CurlSList &&other) { std::swap(slist, other.slist); return *this; }
        CurlSList(const std::vector<std::string> &ss) : slist(nullptr) { extend(ss); }
        CurlSList(const std::map<std::string, std::string> &ss) : slist(nullptr) { extend(ss); }

        void append(const std::string &s) { slist = curl_slist_append(slist, s.c_str()); }
        void extend(const std::vector<std::string> &ss) { for (auto &s: ss) append(s); }
        void extend(const std::map<std::string, std::string> &ss) { for (auto &p: ss) append(p.first + ": " + p.second); }
    };

// TODO: would it be better to construct in one go instead of construct and mutate?
    struct CurlMimePart {
        curl_mimepart *part = nullptr;
        explicit CurlMimePart(curl_mimepart *p) : part(p) {}
        ~CurlMimePart() {}
        CurlMimePart(const CurlMimePart &) = delete;
        CurlMimePart(CurlMimePart &&other) { std::swap(part, other.part); }
        CurlMimePart &operator=(const CurlMimePart &) = delete;
        CurlMimePart &operator=(CurlMimePart&& other) { std::swap(part, other.part); return *this; }

        void name(const char *n) { CurlCheck(curl_mime_name(part, n)); }
        void name(const std::string &n) { name(n.c_str()); }
        void data(const char *d, size_t size) { CurlCheck(curl_mime_data(part, d, size)); }
        void data(const std::vector<char> &d) { data(d.data(), d.size()); }
        void data(const std::string &d) { data(d.c_str(), CURL_ZERO_TERMINATED); }
        void type(const char *t) { CurlCheck(curl_mime_type(part, t)); }
        void type(const std::string &t) { type(t.c_str()); }
        void filename(const char *n) { CurlCheck(curl_mime_filename(part, n)); }
        void filename(const std::string &n) { filename(n.c_str()); }
        void file(const char *path) { CurlCheck(curl_mime_filedata(part, path)); }
        void file(const std::string &path) { file(path.c_str()); }
    };

    struct CurlMime {
        curl_mime *mime = nullptr;
        explicit CurlMime(curl_mime *m) : mime(m) {}
        ~CurlMime() { if (mime) curl_mime_free(mime); }
        CurlMime(const CurlMime &) = delete;
        CurlMime(CurlMime &&other) { std::swap(mime, other.mime); }
        CurlMime &operator=(const CurlMime &) = delete;
        CurlMime &operator=(CurlMime &&other) { std::swap(mime, other.mime); return *this; }

        CurlMimePart part() { return CurlMimePart(CurlCheckCreate(curl_mime_addpart(mime))); }
    };

#if THREAD_LIBRARY != THREAD_LIBRARY_STDCPP
    // TODO: Unfortunately, Utility::Threading doesn't have any functions for
//       non-scoped locking. We could fake it by holding pointers to
//       scoped locks, or we could change that. For now, we're just
//       assuming it's THREAD_LIBRARY_STDCPP and using methods on the
//       mutexes directly.
#error "Curl share locking not implemented for this thread library"
#endif

    struct CurlLocks {
        std::vector<std::shared_timed_mutex> mutexes;
        CurlLocks() : mutexes((int)CURL_LOCK_DATA_LAST) {}
        ~CurlLocks() {}
        CurlLocks(const CurlLocks &) = delete;
        CurlLocks &operator=(const CurlLocks &) = delete;

        void lock_method(curl_lock_data data, curl_lock_access access) {
            auto &mutex = mutexes[(int)data];
            if (access == CURL_LOCK_ACCESS_SHARED)
            mutex.lock_shared();
        else
            mutex.lock();
        }
        static void lock_function(CURL *handle, curl_lock_data data, curl_lock_access access, void *userptr) {
            ((CurlLocks *)userptr)->lock_method(data, access);
        }

        void unlock_method(curl_lock_data data) {
            auto &mutex = mutexes[(int)data];
            // NOTE: We don't know (because curl doesn't tell us) whether
            //       an unlock is shared or single. Fortunately, it is
            //       guaranteed safe to call unlock (for cites to the
            //       standard see https://stackoverflow.com/a/44652576). And
            //       it should be just as efficient. The only real benefit of
            //       the unlock_shared method is that it can fail if there
            //       aren't any shared locks, which could be helpful for
            //       debugging purposes (if we were debugging curl itself).
            mutex.unlock();
        }
        static void unlock_function(CURL *handle, curl_lock_data data, void *userptr) {
            ((CurlLocks *)userptr)->unlock_method(data);
        }
    };

    struct CurlShare {
        CURLSH *share = nullptr;
        CurlShare() : share(CurlCheckCreate(curl_share_init())) {}
        ~CurlShare() { if (share) curl_share_cleanup(share); }
        CurlShare(const CurlShare &) = delete;
        CurlShare(CurlShare &&other) { std::swap(share, other.share); }
        CurlShare &operator=(const CurlShare &) = delete;
        CurlShare &operator=(CurlShare &&other) { std::swap(share, other.share); return *this; }

        typedef void lock_function(CURL *handle, curl_lock_data data, curl_lock_access access, void *userptr);
        typedef void unlock_function(CURL *handle, curl_lock_data data, void *userptr);

        template<typename T>
        void setopt(CURLSHoption option, T parameter) {
            CurlCheckShare(curl_share_setopt(share, option, parameter));
        }
        void setopt(CURLSHoption option, const std::string &parameter) { setopt(option, parameter.c_str()); }

        void setshare(curl_lock_data data) {
            setopt(CURLSHOPT_SHARE, data);
        }

        void setlocks(CurlLocks &locks) {
            setopt(CURLSHOPT_USERDATA, (void *)&locks);
            setopt(CURLSHOPT_LOCKFUNC, (lock_function *)locks.lock_function);
            setopt(CURLSHOPT_UNLOCKFUNC, (unlock_function *)locks.unlock_function);
        }
    };

    struct CurlUrl {
        CURLU *url = nullptr;
        CurlUrl() : url(CurlCheckCreate(curl_url())) {}
        explicit CurlUrl(const char *u) : url(CurlCheckCreate(curl_url())) {
            set(CURLUPART_URL, u, 0);
        }
        explicit CurlUrl(const std::string &u) : url(CurlCheckCreate(curl_url())) {
            set(CURLUPART_URL, u, 0);
        }
        ~CurlUrl() { if (url) curl_url_cleanup(url); }
        CurlUrl(const CurlUrl &) = delete;
        CurlUrl(CurlUrl &&other) { std::swap(url, other.url); }
        CurlUrl &operator=(const CurlUrl &) = delete;
        CurlUrl &operator=(CurlUrl &&other) { std::swap(url, other.url); return *this; }


        void set(CURLUPart part, const std::string &content, unsigned int flags=0) {
            set(part, content.c_str(), flags);
        }
        void set(CURLUPart part, const char *content, unsigned int flags=0) {
            CurlCheckUrl(curl_url_set(url, part, content, flags));
        }
        std::string get(CURLUPart part, unsigned int flags=0) {
            char *content = nullptr;
            CurlCheckUrl(curl_url_get(url, part, &content, flags));
            std::string ret(content ? content : "");
            curl_free(content);
            return ret;
        }
    };

    struct CurlHandle {
        CURL *handle = nullptr;
        CurlHandle() : handle(CurlCheckCreate(curl_easy_init())) {}
        ~CurlHandle() { if (handle) curl_easy_cleanup(handle); }
        CurlHandle(const CurlHandle &) = delete;
        CurlHandle(CurlHandle &&other) { std::swap(handle, other.handle); }
        CurlHandle &operator=(const CurlHandle &) = delete;
        CurlHandle &operator=(CurlHandle &&other) { std::swap(handle, other.handle); return *this; }

        CurlMime mime() { return CurlMime(CurlCheckCreate(curl_mime_init(handle))); }

        std::string info_string(CURLINFO info) {
            char *s = nullptr;
            CurlCheck(curl_easy_getinfo(handle, info, &s));
            return s;
        }

        long info_long(CURLINFO info) {
            long value = 0;
            CurlCheck(curl_easy_getinfo(handle, info, &value));
            return value;
        }

        std::string escape(std::string s) {
            char *output = CurlCheckCreate(curl_easy_escape(handle, s.c_str(), (int) s.size()));
            s = output;
            curl_free(output);
            return s;
        }

        // Provides a string suitable as the query string to append after the ? on a URL,
        // or as an x-www-form-urlencoded POST body.
        std::string formatParameters(const std::map<std::string, std::string> &params) {
            std::stringstream ss;
            bool first = true;
            for (auto &pair: params) {
                if (!first) ss << '&';
                first = false;
                ss << escape(pair.first) << '=' << escape(pair.second);
            }
            return ss.str();
        }

        template<typename T>
        void setopt(CURLoption option, T parameter) {
            CurlCheck(curl_easy_setopt(handle, option, parameter));
        }
        void setopt(CURLoption option, const std::string &parameter) { setopt(option, parameter.c_str()); }
        void setopt(CURLoption option, const CurlSList &parameter) { setopt(option, parameter.slist); }
        void setopt(CURLoption option, const CurlMime &parameter) { setopt(option, parameter.mime); }
        void setopt(CURLoption option, const CurlShare &parameter) { setopt(option, parameter.share); }
    };

    struct CurlGlobals {
        static std::unique_ptr<CurlGlobals> globals;
        static CurlGlobals &Get() {
            if (!globals) {
                throw std::runtime_error("Attempt to use HTTP::Request without calling Initialize");
            }
            return *globals;
        }

        // NOTE: It's still up to the client code to decide what data
        //       should be shared (by calling the setshare method), and
        //       of course to set the share for each handle.
        CurlLocks locks;
        CurlShare share;

        bool usecadirectory;
        bool usecabundle;
        std::string capath;

        std::string description() const {
            std::stringstream ss;
            ss << "CurlGlobals@" << std::hex << (void *)this
               << ": usecadirectory=" << usecadirectory
               << " usecabundle=" << usecabundle
               << " capath=" << capath;
            return ss.str();
        }

        CurlGlobals(std::string path) {
            https_thread_setup();
            curl_global_init(CURL_GLOBAL_ALL);
            https_ca_store_setup(path);
            share.setlocks(locks);
        }
        ~CurlGlobals() {
            https_ca_store_cleanup();
            curl_global_cleanup();
            https_thread_cleanup();
        }

        void https_ca_store_setup(std::string path) {
            usecadirectory = false;
            usecabundle = false;
#if CURL_USING_MBEDTLS
            capath = path;
            usecabundle = true;
#elif CURL_USING_NO_TLS_LIB
            #else
        // TODO: all of it, if anything
        // OpenSSL knows how to find the system CA cert store,
        // but that may not be what we want. Especially if
        // we're using the Apportable rather than native on
        // Android, because then it just finds the system
        // store by hardcoded path, which is not only
        // deprecated, it's also very different from what
        // we'd get on iOS, where user- and carrier-installed
        // certs will be picked up. So, we probably want the
        // same behavior as with MbedTLS. The only difference
        // then is that OpenSSL prefers a directory of PEM
        // files, while MbedTLS requires a single file.
#endif
        }

        void https_ca_store_cleanup() {}
    };

    std::unique_ptr<CurlGlobals> CurlGlobals::globals;

}

