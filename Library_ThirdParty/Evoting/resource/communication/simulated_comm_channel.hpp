#ifndef SIMULATED_COMM_CHANNEL_HPP
#define SIMULATED_COMM_CHANNEL_HPP

#include <queue>
#include <string>

// 前向声明以避免循环引用

class DeviceController;


class SimulatedCommChannel {
public:
    SimulatedCommChannel(){};
    
    DeviceController* end;
    std::queue<std::string> sender_queue;
    std::queue<std::string> receiver_queue;
};

#endif // SIMULATED_COMM_CHANNEL_HPP