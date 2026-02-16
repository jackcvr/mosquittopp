#include <chrono>
#include <print>
#include <thread>

#include "mosq.hpp"

class Client : public mosq::Client<mosq::ExpectedPolicy> {
public:
    using mosq::Client<mosq::ExpectedPolicy>::Client;

    void on_connect(int rc) override {
        if (rc == 0) {
            std::println("Connected. Subscribing...");
            subscribe("sensors/#");
        }
    }

    void on_message(const struct mosquitto_message* msg) override {
        std::string_view payload(static_cast<char*>(msg->payload), msg->payloadlen);
        std::println("[{}] {}", msg->topic, payload);
        std::fflush(stdout);
    }
};

int main() {
    mosq::lib_init();

    Client client;
    if (auto res = client.connect("localhost"); !res) {
        std::println(stderr, "Error: {}", res.error().message());
        return 1;
    }

    std::jthread worker([&client] { client.loop_forever(); });

    std::println("Running...");
    for (int i = 0; i < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::string payload = std::format("Message {}", i);
        client.publish("sensors/test", payload.data(), payload.size(), 1, false);
    }

    client.disconnect();
    client.loop_stop();
    mosq::lib_cleanup();

    return 0;
}
