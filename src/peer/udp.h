
#include "peer/peer.h"
#include <Poco/Net/DatagramSocket.h>

namespace Candy {

class UdpHolder {
public:
    int init();
    void reset();

    void setPort(uint16_t port);
    void setIP(uint32_t ip);

    uint16_t Port();
    uint32_t IP();

    size_t read(UdpMessage &message);
    size_t write(const UdpMessage &message);

private:
    Poco::Net::SocketAddress address;
    Poco::Net::DatagramSocket socket;

    uint16_t port = 0;
    uint32_t ip = 0;
};

} // namespace Candy
