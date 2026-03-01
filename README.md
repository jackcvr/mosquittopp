# Mosquittopp

A modern header-only C++17/23 wrapper for [mosquitto](https://github.com/eclipse-mosquitto/mosquitto).

## Usage Example

```C++
#include <chrono>
#include <iostream>
#include <semaphore>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <format>

#include "mosq.hpp"

struct AppContext {
    std::binary_semaphore is_connected{0};
    std::binary_semaphore is_done{0};
    int message_count = 0;
};

class Client : public mosq::Client<mosq::ExpectedPolicy> {
public:
    using mosq::Client<mosq::ExpectedPolicy>::Client;

    AppContext* context() {
        return static_cast<AppContext*>(userdata());
    }

    void on_connect(int rc) override {
        if (rc == 0) {
            std::cout << "Connected." << std::endl;
            subscribe(nullptr, "sensors/#", 1);
            auto* ctx = context();
            if (ctx) {
                ctx->is_connected.release();
            }
        }
    }

    void on_message(const struct mosquitto_message* msg) override {
        std::string_view payload(static_cast<char*>(msg->payload), msg->payloadlen);
        std::cout << msg->topic << " " << payload << std::endl;
        auto* ctx = context();
        if (ctx && ++ctx->message_count >= 5) {
            ctx->is_done.release();
        }
    }
};

int main() {
    AppContext ctx;
    Client client{&ctx};

    if (auto res = client.connect_async("localhost"); !res) {
        std::cerr << "Error: " << res.error().message() << std::endl;
        return 1;
    }

    std::jthread worker([&client] { client.loop_forever(); });
    std::cout << "Wait connection..." << std::endl;

    ctx.is_connected.acquire();

    for (int i = 0; i < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::string payload = std::format("Message {}", i);
        Client::MidToken token;
        auto res = client.publish(token, "sensors/test", payload.data(), payload.size(), 1);
        if (!res) {
            throw std::runtime_error(res.error().message());
        }
        if (!token.wait(std::chrono::seconds(1))) {
            std::cerr << "Publish timed out!" << std::endl;
        }
    }

    ctx.is_done.acquire();
    client.disconnect();

    return 0;
}
```

## License

[MIT](https://spdx.org/licenses/MIT.html)
