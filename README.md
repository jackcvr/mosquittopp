# Mosquittopp

A modern header-only C++17/23 wrapper for [mosquitto](https://github.com/eclipse-mosquitto/mosquitto).

## Usage Example

```C++
#include <chrono>
#include <print>
#include <semaphore>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

#include "mosq.hpp"

struct AppContext {
    std::binary_semaphore is_connected{0};
    std::binary_semaphore is_done{0};
    int message_count = 0;
};

class Client : public mosq::Client<mosq::ExpectedPolicy> {
public:
    using mosq::Client<mosq::ExpectedPolicy>::Client;

    void on_connect(int rc) override {
        if (rc == 0) {
            std::println("Connected.");
            subscribe("sensors/#", 1);
            auto* ctx = static_cast<AppContext*>(userdata());
            if (ctx) ctx->is_connected.release();
        }
    }

    void on_message(const struct mosquitto_message* msg) override {
        std::string_view payload(static_cast<char*>(msg->payload), msg->payloadlen);
        std::println("{} {}", msg->topic, payload);
        std::fflush(stdout);
        auto* ctx = static_cast<AppContext*>(userdata());
        if (ctx && ++ctx->message_count >= 5) {
            ctx->is_done.release();
        }
    }
};

int main() {
    mosq::lib_init();

    AppContext ctx;
    Client client;
    client.user_data_set(&ctx);

    if (auto res = client.connect_async("localhost"); !res) {
        std::println(stderr, "Error: {}", res.error().message());
        return 1;
    }

    std::jthread worker([&client] { client.loop_forever(); });
    std::println("Running...");

    ctx.is_connected.acquire();

    for (int i = 0; i < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::string payload = "Message " + std::to_string(i);
        auto mid = client.create_mid();
        auto res = client.publish("sensors/test", payload.data(), payload.size(), 1, false, mid);
        if (!res) {
            throw std::runtime_error(res.error().message());
        }
        client.wait_for_mid(mid);
    }

    ctx.is_done.acquire();
    client.disconnect();
    mosq::lib_cleanup();

    return 0;
}
```

## License

[MIT](https://spdx.org/licenses/MIT.html)
