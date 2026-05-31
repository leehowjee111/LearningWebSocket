#include <algorithm>
#include <asm-generic/socket.h>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
constexpr int PORT = 8080;
constexpr uint8_t WS_FIN_MASK = 0x80;
constexpr uint8_t WS_OPCODE_MASK = 0x0F;
constexpr uint8_t WS_MASK_FLAG = 0x80;
constexpr uint8_t WS_PAYLOAD_LEN_MASK = 0x7F;
constexpr unsigned char WS_OPCODE_TEXT = 0x8;
constexpr unsigned char WS_OPCODE_CLOSE = 0x1;
constexpr size_t WS_HEADER_MIN_LEN = 2;
constexpr size_t WS_MASK_KEY_LEN = 4;
constexpr size_t FRAME_LEN = 256;
constexpr size_t BUFFER_LEN = 4096;
// 算法如下：Accept = Base64( SHA1( client_key +
// "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ) ) B64 固定常数
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// 仅学习用，实战直接上库。
std::string base64_encode(const unsigned char *data, size_t len) {
  std::string ret;
  size_t i = 0;
  unsigned char c3[3], c4[4];
  while (len--) {
    c3[i++] = *(data++);
    if (i == 3) {
      c4[0] = (c3[0] & 0xfc) >> 2;
      c4[1] = ((c3[0] & 0x03) << 4) + ((c3[1] & 0xf0) >> 4);
      c4[2] = ((c3[1] & 0x0f) << 2) + ((c3[2] & 0xc0) >> 6);
      c4[3] = c3[2] & 0x3f;
      for (int j = 0; j < 4; j++)
        ret += B64[c4[j]];
      i = 0;
    }
  }
  if (i) {
    for (int j = i; j < 3; j++)
      c3[j] = '\0';
    c4[0] = (c3[0] & 0xfc) >> 2;
    c4[1] = ((c3[0] & 0x03) << 4) + ((c3[1] & 0xf0) >> 4);
    c4[2] = ((c3[1] & 0x0f) << 2) + ((c3[2] & 0xc0) >> 6);
    c4[3] = c3[2] & 0x3f;
    for (int j = 0; j < (i + 1); j++)
      ret += B64[c4[j]];
    while (i++ < 3)
      ret += '=';
  }
  return ret;
}

// SHA-1 计算
std::string sha1(const std::string &input) {
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
  EVP_DigestUpdate(ctx, input.c_str(), input.size());
  EVP_DigestFinal_ex(ctx, hash, &len);
  EVP_MD_CTX_free(ctx);
  return std::string((char *)hash, len); // 二进制哈希值，20字节
}
// 算法如下：Accept = Base64( SHA1( client_key +
// "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ) )
//  计算 Sec-WebSocket-Accept
std::string compute_accept_key(const std::string &client_key) {
  std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::string hash = sha1(client_key + magic);
  return base64_encode((unsigned char *)hash.c_str(), hash.size());
}
using std::cerr;
using std::cout;
// 启动服务端，创建socket并且监听客户端连接
int serverInit() {
  int socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd_ < 0) {
    cerr << "create socket error\n";
    close(socket_fd_);
    return -1;
  }
  struct sockaddr_in server_addr_;
  memset(&server_addr_, 0, sizeof(server_addr_));
  server_addr_.sin_family = AF_INET;
  server_addr_.sin_port = htons(PORT);
  server_addr_.sin_addr.s_addr = htonl(INADDR_ANY);
  int opt = 1;
  if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    cerr << "setsockopt error\n";
    close(socket_fd_);
    return -1;
  }
  if (bind(socket_fd_, (struct sockaddr *)&server_addr_, sizeof(server_addr_)) <
      0) {
    cerr << "bind socket error\n";
    close(socket_fd_);
    return -1;
  }
  if (listen(socket_fd_, 5) < 0) {
    cerr << "listen client error\n";
    close(socket_fd_);
    return -1;
  }
  cout << "Server listen on port 8080\n";
  return socket_fd_;
}
// 处理读取的数据，第一个参数是来源的描述符，第二个是需要写入的缓冲区，最后一个是需要接受的大小
// 返回bool值
// 保证每次会接收到固定长度的数据，防止粘包，拆包
bool read_exact(int fd_, void *buffer, size_t n) {
  size_t total = 0;
  while (total < n) {
    size_t r = recv(fd_, (char *)buffer + total, n - total, 0);
    if (r <= 0)
      return false;
    total += r;
  }
  return true;
}
// 客户端向服务器发送帧
// 传入来源的客户端，传入一个接收消息的字符串
bool read_ws_frame(int client_fd_, std::string &out) {
  unsigned char header[WS_HEADER_MIN_LEN];
  int n = recv(client_fd_, header, 2, 0);
  if (n < 0) {
    cerr << "header size error\n";
    return false;
  }
  // FIN表示完整帧还是不完整,1bit
  unsigned char FIN = (header[0] & WS_FIN_MASK) != 0;
  // 数据类型opcode 0x1是文本，0x8是结束,1bit
  unsigned char opcode = header[0] & WS_OPCODE_MASK;
  // 一位掩码
  bool masked = (header[1] & WS_MASK_FLAG) != 0;
  // 数据长度，现在姑且认为小于127,7bits
  unsigned char payload_len = header[1] & WS_PAYLOAD_LEN_MASK;
  cout << "FIN :" << (int)FIN << "opcode :" << (int)opcode << "mask :" << masked
       << "payload_len :" << (int)payload_len << "\n";
  if (opcode == WS_OPCODE_TEXT) {
    cerr << "websocket close\n";
    return false;
  }
  if (opcode != WS_OPCODE_CLOSE) {
    cerr << "ignore expect text\n";
    return false;
  }
  unsigned char mask[WS_MASK_KEY_LEN] = {0};
  // 接受掩码的数据
  if (masked) {
    if (recv(client_fd_, mask, WS_MASK_KEY_LEN, 0) < 0) {
      cerr << "msg size error\n";
      return false;
    }
  } else {
    cerr << "client_msg must be masked\n";
    return false;
  }
  // 接收有掩码数据
  std::string payload(payload_len, '\0');
  if (payload_len > 0) {
    recv(client_fd_, &payload[0], payload_len, 0);
  }
  // XOR还原数据
  for (int i = 0; i < payload_len; ++i) {
    payload[i] ^= mask[i % WS_MASK_KEY_LEN];
  }
  out = std::move(payload);
  return true;
}
// 服务器向客户端发送数据，不需要掩码。但是反过来必须需要
// 传入需要发送的客户端，传入数据
bool send_ws_frame(int client_fd_, std::string payload) {
  unsigned char frame[FRAME_LEN];
  size_t pos = 0;
  // FIN = 1 , opcode = 0x1
  frame[pos++] = 0x81;
  // 无掩码的数据长度
  frame[pos++] = static_cast<unsigned char>(payload.size());
  // 数据传入
  memcpy(&frame[pos], payload.data(), payload.size());
  pos += payload.size();
  // 发送pos长度的数据,MSG_NOSIGNAL表示没有数据会返回-1,不加会之间杀死进程，这样写方便以后回收
  return send(client_fd_, frame, pos, MSG_NOSIGNAL) == (ssize_t)pos;
};
// 客户端容器
std::vector<int> client_vec;
std::mutex mtx;
// 广播，send_fd表示数据来源，msg表示数据
// 该函数会将一条信息发送给所有的客户端
void broadcast(int send_fd, const std::string &msg) {
  std::lock_guard<std::mutex> locker(mtx);
  std::string full;
  if (send_fd == -1) {
    full = "系统：" + msg;
  } else {
    full = "用户[" + std::to_string(send_fd) + "]: " + msg;
  }
  for (int fd : client_vec) {
    if (!send_ws_frame(fd, full)) {
      continue;
    }
  }
}
// 初始化客户端，包括http的握手（处理acceptKey），连接websocket
void client_Init(int client_fd_) {
  char buffer[BUFFER_LEN];
  memset(buffer, 0, sizeof(buffer));
  int n = recv(client_fd_, &buffer, sizeof(buffer) - 1, 0);
  if (n < 0) {
    cerr << "buffer size error\n";
    return;
  }
  buffer[n] = '\0';
  const char *key_marker = "Sec-WebSocket-Key: ";
  char *key_start = strstr(buffer, key_marker);
  if (!key_start) {
    cerr << "key_start is null\n";
    return;
  }
  key_start += strlen(key_marker);
  const char *key_marker_end = "\r\n";
  char *key_end = strstr(key_start, key_marker_end);
  if (!key_end) {
    cerr << "key_end is null\n";
    return;
  }
  std::string key(key_start, key_end - key_start);
  cout << "client_key is : " << key << "\n";
  // 根据算法计算accept_key
  std::string accept_key = compute_accept_key(key);
  cout << "doing compute_accept_key\n";
  // response:
  std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
                         "Upgrade: websocket\r\n"
                         "Connection: Upgrade\r\n"
                         "Sec-WebSocket-Accept: " +
                         accept_key +
                         "\r\n"
                         "\r\n";
  send(client_fd_, response.c_str(), response.size(), MSG_NOSIGNAL);
  cout << "send response :101\n";
  // 加入客户端组中，注意多线程考虑临界资源情况
  {
    std::lock_guard<std::mutex> locker(mtx);
    client_vec.push_back(client_fd_);
  }
  cout << "用户" << client_fd_ << "进入\n";
  broadcast(-1, "用户" + std::to_string(client_fd_) + "进入");
  std::string msg;
  // 读取消息
  while (read_ws_frame(client_fd_, msg)) {
    cout << "用户" << client_fd_ << ": " << msg << "\n";
    broadcast(client_fd_, msg);
  }

  cout << "用户" << client_fd_ << "退出\n";
  // 关闭连接即删除
  {
    std::lock_guard<std::mutex> locker(mtx);
    auto it = std::find(client_vec.begin(), client_vec.end(), client_fd_);
    if (it != client_vec.end())
      client_vec.erase(it);
  }
  broadcast(-1, "用户" + std::to_string(client_fd_) + "退出");
  close(client_fd_);
}

int main(int argc, char *argv[]) {
  signal(SIGPIPE, SIG_IGN);
  int socket_fd_ = serverInit();
  if (socket_fd_ < 0) {
    return 1;
  }

  cout << "聊天室启动: ws://localhost:8080\n";
  cout << "开多个 Firefox 标签页测试多人聊天\n\n";
  // cout << "receive " << n << " bytes\n" << buffer << "\n";
  //  send(client_fd_, &buffer, sizeof(buffer), 0);
  //  websocket帧 FIN1 RSV3 opcode4 MASK1 payload_len7
  //  处理websocket帧
  while (true) {
    struct sockaddr_in client_addr_;
    socklen_t client_addr_len_ = sizeof(client_addr_);
    int client_fd_ =
        accept(socket_fd_, (struct sockaddr *)&client_addr_, &client_addr_len_);
    if (client_fd_ < 0) {
      cerr << "accept error\n";
      close(client_fd_);
      continue;
    }
    // 创建线程
    std::thread(client_Init, client_fd_).detach();
  }
  close(socket_fd_);
  return 0;
}
