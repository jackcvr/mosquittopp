#pragma once

#include <mosquitto.h>

#if LIBMOSQUITTO_VERSION_NUMBER < 2000011 || LIBMOSQUITTO_VERSION_NUMBER > 3000000
#error "Unsupported libmosquitto version: must be >=2.0.11 and <3"
#endif

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

#if __cplusplus >= 202302L && __has_include(<expected>)
#include <expected>
#define MOSQUITTOPP_HAS_EXPECTED
#endif

namespace mosq {

inline const char* strerror(int err) noexcept {
    return mosquitto_strerror(err);
}

inline const char* connack_string(int connack_code) noexcept {
    return mosquitto_connack_string(connack_code);
}

class MosquittoException : public std::runtime_error {
public:
    explicit MosquittoException(const std::string& msg, int code = errno)
        : std::runtime_error(msg + ": " + strerror(code)), code_(code) {}

    auto code() const noexcept {
        return code_;
    }

private:
    int code_;
};

struct ExceptionPolicy {
    static int handle(int value, const char* msg) {
        if (value != MOSQ_ERR_SUCCESS) {
            throw MosquittoException(msg, value);
        }
        return value;
    }
};

struct ValuePolicy {
    static int handle(int value, const char*) noexcept {
        return value;
    }
};

#ifdef MOSQUITTOPP_HAS_EXPECTED
class MosquittoError {
public:
    MosquittoError(int code) : code_(code) {}
    auto code() const noexcept {
        return code_;
    }
    auto message() const noexcept {
        return strerror(code_);
    }

private:
    int code_;
};

struct ExpectedPolicy {
    static std::expected<int, MosquittoError> handle(int value, const char*) noexcept {
        if (value != MOSQ_ERR_SUCCESS) {
            return std::unexpected(MosquittoError(value));
        }
        return value;
    }
};
#endif

struct Version {
    int major;
    int minor;
    int revision;
    int number;
};

inline Version lib_version() noexcept {
    int maj, min, rev;
    int num = mosquitto_lib_version(&maj, &min, &rev);
    return {maj, min, rev, num};
}

auto lib_init() {
    return ExceptionPolicy::handle(mosquitto_lib_init(), "Library init failed");
}

auto lib_cleanup() noexcept {
    return mosquitto_lib_cleanup();
}

struct MosqDeleter {
    void operator()(struct mosquitto* m) const noexcept {
        if (m) mosquitto_destroy(m);
    }
};

struct NullMutex {
    void lock() noexcept {}
    void unlock() noexcept {}
};

template <typename ErrorPolicy = ExceptionPolicy, bool ThreadSafe = true>
class Client {
public:
    class MidToken {
    public:
        MidToken() : client_(nullptr), mid_(0) {}

        MidToken(const MidToken&) = delete;
        MidToken& operator=(const MidToken&) = delete;

        ~MidToken() {
            if (client_) {
                std::lock_guard lock(client_->mid_mtx_);
                client_->pending_mids_.erase(this);
            }
        }

        void assign(Client& c) {
            client_ = &c;
            std::lock_guard lock(client_->mid_mtx_);
            client_->pending_mids_.insert(this);
        }

        template <typename Rep, typename Period>
        bool wait(const std::chrono::duration<Rep, Period>& timeout) {
            if (mid_ == 0 || !client_) return false;
            std::unique_lock lock(client_->mid_mtx_);
            return client_->mid_cv_.wait_for(
                lock, timeout, [this] { return !client_->pending_mids_.contains(this); });
        }

        void wait() {
            if (mid_ == 0 || !client_) return;
            std::unique_lock lock(client_->mid_mtx_);
            client_->mid_cv_.wait(lock, [this] { return !client_->pending_mids_.contains(this); });
        }

        operator int*() {
            return &mid_;
        }

        int id() const {
            return mid_;
        }

    private:
        friend class Client;
        Client* client_;
        int mid_;
    };

    explicit Client(void* userdata) : Client("", true, userdata) {}

    explicit Client(const std::string& id = "", bool clean_session = true,
                    void* userdata = nullptr) {
        const char* id_str = id.empty() ? nullptr : id.c_str();
        struct mosquitto* m = mosquitto_new(id_str, clean_session, userdata);
        if (!m) {
            throw std::system_error(errno, std::generic_category(),
                                    "Failed to create Mosquitto instance");
        }
        mosq_.reset(m);
        if constexpr (ThreadSafe) {
            threaded_set(true);
        }
        register_instance(m, this);
        setup_callbacks();
    }

    virtual ~Client() {
        if (mosq_) unregister_instance(mosq_.get());
    }

    struct mosquitto* get() const noexcept {
        return mosq_.get();
    }

    auto reinitialise(const std::string& id, bool clean_session) {
        const char* id_str = id.empty() ? nullptr : id.c_str();
        int rc = mosquitto_reinitialise(mosq_.get(), id_str, clean_session, this);
        auto res = ErrorPolicy::handle(rc, "Reinitialise failed");
        if (res) {
            setup_callbacks();
        }
        return res;
    }

    auto connect(const std::string& host, int port = 1883, int keepalive = 60) {
        return ErrorPolicy::handle(mosquitto_connect(mosq_.get(), host.c_str(), port, keepalive),
                                   "Connect failed");
    }

    auto connect(const std::string& host, int port, int keepalive,
                 const std::string& bind_address) {
        return ErrorPolicy::handle(mosquitto_connect_bind(mosq_.get(), host.c_str(), port,
                                                          keepalive, bind_address.c_str()),
                                   "Connect bind failed");
    }

    auto connect_async(const std::string& host, int port = 1883, int keepalive = 60) {
        return ErrorPolicy::handle(
            mosquitto_connect_async(mosq_.get(), host.c_str(), port, keepalive),
            "Async connect failed");
    }

    auto connect_async(const std::string& host, int port, int keepalive,
                       const std::string& bind_address) {
        return ErrorPolicy::handle(mosquitto_connect_bind_async(mosq_.get(), host.c_str(), port,
                                                                keepalive, bind_address.c_str()),
                                   "Async connect bind failed");
    }

    auto reconnect() {
        return ErrorPolicy::handle(mosquitto_reconnect(mosq_.get()), "Reconnect failed");
    }

    auto reconnect_async() {
        return ErrorPolicy::handle(mosquitto_reconnect_async(mosq_.get()),
                                   "Reconnect async failed");
    }

    auto disconnect() {
        return ErrorPolicy::handle(mosquitto_disconnect(mosq_.get()), "Disconnect failed");
    }

    auto publish(int* mid, const std::string& topic, const void* payload, int payloadlen,
                 int qos = 0, bool retain = false) {
        int rc =
            mosquitto_publish(mosq_.get(), mid, topic.c_str(), payloadlen, payload, qos, retain);
        return ErrorPolicy::handle(rc, "Publish failed");
    }

    auto publish(MidToken& token, const std::string& topic, const void* payload, int payloadlen,
                 int qos = 0, bool retain = false) {
        token.assign(*this);
        int rc =
            mosquitto_publish(mosq_.get(), token, topic.c_str(), payloadlen, payload, qos, retain);
        return ErrorPolicy::handle(rc, "Publish failed");
    }

    auto subscribe(int* mid, const std::string& sub, int qos = 0) {
        return ErrorPolicy::handle(mosquitto_subscribe(mosq_.get(), mid, sub.c_str(), qos),
                                   "Subscribe failed");
    }

    auto subscribe(MidToken& token, const std::string& sub, int qos = 0) {
        token.assign(*this);
        return ErrorPolicy::handle(mosquitto_subscribe(mosq_.get(), token, sub.c_str(), qos),
                                   "Subscribe failed");
    }

    auto unsubscribe(int* mid, const std::string& sub) {
        return ErrorPolicy::handle(mosquitto_unsubscribe(mosq_.get(), mid, sub.c_str()),
                                   "Unsubscribe failed");
    }

    auto unsubscribe(MidToken& token, const std::string& sub) {
        token.assign(*this);
        return ErrorPolicy::handle(mosquitto_unsubscribe(mosq_.get(), token, sub.c_str()),
                                   "Unsubscribe failed");
    }

    auto will_set(const std::string& topic, int payloadlen, const void* payload, int qos,
                  bool retain) {
        return ErrorPolicy::handle(
            mosquitto_will_set(mosq_.get(), topic.c_str(), payloadlen, payload, qos, retain),
            "Will set failed");
    }

    auto will_clear() {
        return ErrorPolicy::handle(mosquitto_will_clear(mosq_.get()), "Will clear failed");
    }

    auto username_pw_set(const std::string& username, const std::string& password = "") {
        const char* pw = password.empty() ? nullptr : password.c_str();
        return ErrorPolicy::handle(mosquitto_username_pw_set(mosq_.get(), username.c_str(), pw),
                                   "Username/password set failed");
    }

    auto loop(int timeout = -1, int max_packets = 1) {
        return ErrorPolicy::handle(mosquitto_loop(mosq_.get(), timeout, max_packets),
                                   "Loop failed");
    }

    auto loop_misc() {
        return ErrorPolicy::handle(mosquitto_loop_misc(mosq_.get()), "Loop misc failed");
    }

    auto loop_read(int max_packets = 1) {
        return ErrorPolicy::handle(mosquitto_loop_read(mosq_.get(), max_packets),
                                   "Loop read failed");
    }

    auto loop_write(int max_packets = 1) {
        return ErrorPolicy::handle(mosquitto_loop_write(mosq_.get(), max_packets),
                                   "Loop write failed");
    }

    auto loop_forever(int timeout = -1, int max_packets = 1) {
        return ErrorPolicy::handle(mosquitto_loop_forever(mosq_.get(), timeout, max_packets),
                                   "Loop forever failed");
    }

    auto loop_start() {
        return ErrorPolicy::handle(mosquitto_loop_start(mosq_.get()), "Loop start failed");
    }

    auto loop_stop(bool force = false) {
        return ErrorPolicy::handle(mosquitto_loop_stop(mosq_.get(), force), "Loop stop failed");
    }

    int socket() const noexcept {
        return mosquitto_socket(mosq_.get());
    }

    bool want_write() const noexcept {
        return mosquitto_want_write(mosq_.get());
    }

    auto opts_set(enum mosq_opt_t option, void* value) {
        return ErrorPolicy::handle(mosquitto_opts_set(mosq_.get(), option, value),
                                   "Opts set failed");
    }

    auto threaded_set(bool threaded) {
        return ErrorPolicy::handle(mosquitto_threaded_set(mosq_.get(), threaded),
                                   "Threaded set failed");
    }

    void reconnect_delay_set(unsigned int reconnect_delay, unsigned int reconnect_delay_max,
                             bool reconnect_exponential_backoff) {
        mosquitto_reconnect_delay_set(mosq_.get(), reconnect_delay, reconnect_delay_max,
                                      reconnect_exponential_backoff);
    }

    auto max_inflight_messages_set(unsigned int max_inflight_messages) {
        return ErrorPolicy::handle(
            mosquitto_max_inflight_messages_set(mosq_.get(), max_inflight_messages),
            "Max inflight set failed");
    }

    void message_retry_set(unsigned int message_retry) {
        mosquitto_message_retry_set(mosq_.get(), message_retry);
    }

    void user_data_set(void* userdata) {
        mosquitto_user_data_set(mosq_.get(), userdata);
    }

    void* userdata() const {
        return mosquitto_userdata(mosq_.get());
    }

    auto socks5_set(const std::string& host, int port = 1080, const std::string& username = "",
                    const std::string& password = "") {
        const char* u = username.empty() ? nullptr : username.c_str();
        const char* p = password.empty() ? nullptr : password.c_str();
        return ErrorPolicy::handle(mosquitto_socks5_set(mosq_.get(), host.c_str(), port, u, p),
                                   "SOCKS5 set failed");
    }

    auto tls_set(const std::string& cafile, const std::string& capath = "",
                 const std::string& certfile = "", const std::string& keyfile = "",
                 int (*pw_callback)(char* buf, int size, int rwflag, void* userdata) = nullptr) {
        const char* cap = capath.empty() ? nullptr : capath.c_str();
        const char* cert = certfile.empty() ? nullptr : certfile.c_str();
        const char* key = keyfile.empty() ? nullptr : keyfile.c_str();
        return ErrorPolicy::handle(
            mosquitto_tls_set(mosq_.get(), cafile.c_str(), cap, cert, key, pw_callback),
            "TLS set failed");
    }

    auto tls_opts_set(int cert_reqs, const std::string& tls_version = "",
                      const std::string& ciphers = "") {
        const char* tv = tls_version.empty() ? nullptr : tls_version.c_str();
        const char* c = ciphers.empty() ? nullptr : ciphers.c_str();
        return ErrorPolicy::handle(mosquitto_tls_opts_set(mosq_.get(), cert_reqs, tv, c),
                                   "TLS opts set failed");
    }

    auto tls_insecure_set(bool value) {
        return ErrorPolicy::handle(mosquitto_tls_insecure_set(mosq_.get(), value),
                                   "TLS insecure set failed");
    }

    auto tls_psk_set(const std::string& psk, const std::string& identity,
                     const std::string& ciphers = "") {
        const char* c = ciphers.empty() ? nullptr : ciphers.c_str();
        return ErrorPolicy::handle(
            mosquitto_tls_psk_set(mosq_.get(), psk.c_str(), identity.c_str(), c),
            "TLS PSK set failed");
    }

    virtual void on_connect(int /*rc*/) {}
    virtual void on_disconnect(int /*rc*/) {}
    virtual void on_publish(int /*mid*/) {}
    virtual void on_message(const struct mosquitto_message* /*message*/) {}
    virtual void on_subscribe(int /*mid*/, int /*qos_count*/, const int* /*granted_qos*/) {}
    virtual void on_unsubscribe(int /*mid*/) {}
    virtual void on_log(int /*level*/, const char* /*str*/) {}

protected:
    using MutexType = std::conditional_t<ThreadSafe, std::mutex, NullMutex>;

    static inline MutexType registry_mtx;
    static inline std::unordered_map<struct mosquitto*, Client*> registry;

    std::unique_ptr<struct mosquitto, MosqDeleter> mosq_;
    std::mutex mid_mtx_;
    std::condition_variable mid_cv_;
    std::unordered_set<MidToken*> pending_mids_;

    void resolve_mid(int mid) {
        std::lock_guard lock(mid_mtx_);
        auto it = std::ranges::find_if(pending_mids_, [mid](auto* t) { return t->id() == mid; });
        if (it != pending_mids_.end()) {
            pending_mids_.erase(it);
            mid_cv_.notify_all();
        }
    }

    static void register_instance(struct mosquitto* m, Client* obj) {
        std::lock_guard lock(registry_mtx);
        registry[m] = obj;
    }

    static void unregister_instance(struct mosquitto* m) {
        std::lock_guard lock(registry_mtx);
        registry.erase(m);
    }

    static Client* find_instance(struct mosquitto* m) {
        std::lock_guard lock(registry_mtx);
        auto it = registry.find(m);
        return (it != registry.end()) ? it->second : nullptr;
    }

    void setup_callbacks() {
        mosquitto_connect_callback_set(mosq_.get(), [](struct mosquitto* m, void*, int rc) {
            if (auto* self = find_instance(m)) self->on_connect(rc);
        });

        mosquitto_disconnect_callback_set(mosq_.get(), [](struct mosquitto* m, void*, int rc) {
            if (auto* self = find_instance(m)) self->on_disconnect(rc);
        });

        mosquitto_publish_callback_set(mosq_.get(), [](struct mosquitto* m, void*, int mid) {
            if (auto* self = find_instance(m)) {
                self->resolve_mid(mid);
                self->on_publish(mid);
            }
        });

        mosquitto_message_callback_set(
            mosq_.get(), [](struct mosquitto* m, void*, const struct mosquitto_message* msg) {
                if (auto* self = find_instance(m)) self->on_message(msg);
            });

        mosquitto_subscribe_callback_set(mosq_.get(), [](struct mosquitto* m, void*, int mid,
                                                         int qos_count, const int* granted_qos) {
            if (auto* self = find_instance(m)) {
                self->resolve_mid(mid);
                self->on_subscribe(mid, qos_count, granted_qos);
            }
        });

        mosquitto_unsubscribe_callback_set(mosq_.get(), [](struct mosquitto* m, void*, int mid) {
            if (auto* self = find_instance(m)) {
                self->resolve_mid(mid);
                self->on_unsubscribe(mid);
            }
        });

        mosquitto_log_callback_set(mosq_.get(),
                                   [](struct mosquitto* m, void*, int level, const char* str) {
                                       if (auto* self = find_instance(m)) self->on_log(level, str);
                                   });
    }
};

}  // namespace mosq
