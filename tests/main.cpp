#include <chrono>
#include <iostream>
#include <semaphore>
#include <string>
#include <string_view>
#include <thread>

#include "mosq.hpp"

struct AppContext {
    std::binary_semaphore is_done{0};
    int message_count = 0;
};

class Client : public mosq::Client<mosq::ExpectedPolicy> {
public:
    using mosq::Client<mosq::ExpectedPolicy>::Client;

    void on_connect(int rc) override {
        if (rc == 0) {
            std::cout << "Connected." << std::endl;
            subscribe("sensors/#", 1);
        }
    }

    void on_message(const struct mosquitto_message* msg) override {
        std::string_view payload(static_cast<char*>(msg->payload), msg->payloadlen);
        std::cout << msg->topic << " " << payload << std::endl;
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
    client.threaded_set(true);
    client.user_data_set(&ctx);
    if (auto res = client.connect_async("localhost"); !res) {
        std::cerr << "Error: " << res.error().message() << std::endl;
        return 1;
    }

    std::jthread worker([&client] { client.loop_forever(); });
    std::cout << "Running..." << std::endl;

    for (int i = 0; i < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::string payload = "Message " + std::to_string(i);
        client.publish("sensors/test", payload.data(), payload.size(), 1, false);
    }
    ctx.is_done.acquire();
    client.disconnect();
    mosq::lib_cleanup();

    return 0;
}
