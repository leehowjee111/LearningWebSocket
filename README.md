## C++ WebSocket初体验
> 手写的一个及其简陋的多人聊天室（仅限于控制台），记录一下第一次学习linux网络编程和WebSocket，使用了OpenSSL和thread
##### 编译
g++ -g socket_test.cpp -o socket_test -lcrypto -lpthread

##### 运行
./socket_test 启动服务器

##### 实现功能
socket_init 创建一个socket并监听客户端连接
client_init 对于已经连接的客户端进行HTTP握手连接，管理客户端生命周期，读取消息，每个客户端使用一个线程
compute_accept_key 算法Accept = Base64( SHA1( client_key +"258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ) )的实现
read_exact 读取指定大小的数据，防粘包，拆包
read_ws_frame 读取来自客户端的websocket帧,要解掩码
send_ws_frame 服务器向客户端发送websocket帧，无需掩码
broadcast 向多个客户端发送消息
