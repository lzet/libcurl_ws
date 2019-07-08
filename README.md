# websocket over libcurl

### depencies
- libcurl

### usage
```
    WebSocketIO ws("wss://echo.websocket.org", "chat",
       [](const std::string &err){ // Error callback
        std::cerr << "E -> " << err << std::endl;
    }, [&](const std::string &data){ // Answer callback
        std::cerr << "D -> " << data << std::endl;
    }, false /*no async*/);
    if(ws.start()) {
       ws.write("Hello world!");
       //...
       ws.write("Bye world!");
    }
    ws.stop();
```
