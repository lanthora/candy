# candy-service

**[中文文档](README.zh-CN.md)**

Another implementation of the Candy client.

- **Stateless**: The process itself does not persist any data. Data is lost after process restart and requires external maintenance of network configuration information
- **API Interaction**: Provides HTTP API interaction interface externally, enabling remote control and access

## API

### Help

Linux:

```bash
candy-service --help
```

Windows:

```bat
candy-service /help
```

The **id** in the request response is used to identify the network connection. Different identifiers can be used to join multiple networks simultaneously. This identifier is used to view status and close networks.

### Run

The meaning of startup parameters is the same as the [configuration file](../candy.cfg), with two additional configuration items:

- **vmac**: Used to identify a unique device. When two devices with different vmac in the same network apply for the same IP address, the latter will report an IP conflict. It is a 16-character random alphanumeric string that needs to be persisted. It is recommended to generate it when starting the process for the first time.
- **expt**: The expected IP address to use. This parameter is used to implement priority allocation of previously used addresses. It is actively reported to the server by the client and can be empty. It is recommended that when the server randomly assigns an address, view the assigned address through `/api/status` and save it, and carry this address when connecting next time.

`POST /api/run`

```json
{
  "id": "test",
  "config": {
    "mode": "client",
    "websocket": "wss://canets.org",
    "password": "",
    "name": "",
    "tun": "",
    "stun": "stun://stun.canets.org",
    "discovery": 300,
    "route": 5,
    "port": 0,
    "localhost": "",
    "mtu": 1400,
    "expt": "",
    "vmac": "16-char rand str"
  }
}
```

Response:

```json
{
  "id": "test",
  "message": "success"
}
```

### Status

`POST /api/status`

```json
{
  "id": "test"
}
```

Response:

```json
{
  "id": "test",
  "message": "success",
  "status": {
    "address": "192.168.202.1/24"
  }
}
```

### Shutdown

`POST /api/shutdown`

```json
{
  "id": "test"
}
```

Response:

```json
{
  "id": "test",
  "message": "success"
}
```
