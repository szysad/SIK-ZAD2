#include "StreamReceiver.h"
#include <iostream>

data_accesor mp3_acc = [](std::string &data) {
    fwrite(data.c_str(), 1, data.length(), stdout);
};

data_accesor meta_acc = [](std::string &data) {
    fwrite(data.c_str(), 1, data.length(), stderr);
};

int main() {

    std::string radio_addr("239.10.11.12");
    uint16_t radio_port = 54321;

    StreamReceiver receiver(radio_addr.c_str(), radio_port, 5);
    auto radios = receiver.get_radios();


    if (radios.empty()) {
        std::cout << "no radios" << std::endl;
        return 0;
    }
    
    radio r = radios.front();
    //std::cout << "found radio: " << r.first << std::endl;
    receiver.connect_to_radio(r, mp3_acc, meta_acc);
    while (receiver.is_connected()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    return 0;
}