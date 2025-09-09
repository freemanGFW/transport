# 国密TLS监听器集成指南

## 概述

本文档描述了如何在 OpenZiti Transport 框架中集成国密TLS监听器支持。与拨号器类似，监听器现在也支持智能检测和自动选择标准TLS或国密TLS。

## 主要特性

### 1. 智能TLS协议选择
- **自动检测**: 监听器启动时自动检测是否有可用的国密TLS证书
- **优雅回退**: 如果国密TLS不可用，自动回退到标准TLS
- **无缝集成**: 对现有代码完全透明，无需修改调用方式

### 2. 双协议支持
- **标准TLS**: 继续支持现有的TLS 1.2/1.3协议
- **国密TLS**: 支持基于SM2/SM3/SM4算法的国密TLS协议
- **并行运行**: 可以同时运行标准TLS和国密TLS监听器

## 使用方法

### 1. 基本监听器（自动选择）

```go
import (
    "github.com/openziti/transport/v2/tls"
    "github.com/openziti/identity"
)

// 自动选择最佳TLS实现
closer, err := tls.Listen(bindAddress, name, identity, acceptF, protocols...)
if err != nil {
    log.Fatal(err)
}
defer closer.Close()
```

### 2. 显式国密TLS监听器

```go
import (
    "github.com/tjfoc/gmsm/gmtls"
    "github.com/openziti/transport/v2/tls"
)

// 创建国密TLS配置
gmConfig := &gmtls.Config{
    Certificates: []gmtls.Certificate{cert},
}

// 创建国密TLS监听器
listener, err := tls.ListenGMTLS(bindAddress, name, gmConfig)
if err != nil {
    log.Fatal(err)
}
defer listener.Close()
```

### 3. 标准TLS监听器

```go
import (
    "crypto/tls"
    "github.com/openziti/transport/v2/tls"
)

// 创建标准TLS配置
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
}

// 创建标准TLS监听器
listener, err := tls.ListenTLS(bindAddress, name, tlsConfig)
if err != nil {
    log.Fatal(err)
}
defer listener.Close()
```

## 证书配置

### 环境变量配置

```bash
# 国密TLS服务器证书
export GMTLS_SERVER_CERT_FILE="/path/to/gm-server.crt"
export GMTLS_SERVER_KEY_FILE="/path/to/gm-server.key"
```

### 默认文件路径

监听器会自动搜索以下路径的国密证书：

1. `./certs/gm-server.crt` 和 `./certs/gm-server.key`
2. `./gmtls/server.crt` 和 `./gmtls/server.key`
3. `/etc/ssl/gmtls/server.crt` 和 `/etc/ssl/gmtls/server.key`
4. `./gm-server.crt` 和 `./gm-server.key`

## 技术实现详情

### 1. 架构变化

```
原始架构:
Listen() -> registerWithSharedListener() -> tls.Listen() -> processConn()

新架构:
Listen() -> getOptimalServerTLSConfig() -> registerWithSharedListener() 
    ├── 国密TLS: gmtls.Listen() -> runGMAccept() -> processGMConn()
    └── 标准TLS: tls.Listen() -> runAccept() -> processConn()
```

### 2. 关键组件

#### protocolHandler 结构体增强
```go
type protocolHandler struct {
    name     string
    listener *sharedListener
    tls      *tls.Config      // 标准TLS配置
    gmtls    *gmtls.Config    // 国密TLS配置
    isGM     bool             // 是否使用国密TLS
    acceptF  func(conn transport.Conn)
    closed   atomic.Bool
}
```

#### sharedListener 结构体增强
```go
type sharedListener struct {
    log      logrus.FieldLogger
    address  string
    tlsCfg   *tls.Config      // 标准TLS配置
    gmtlsCfg *gmtls.Config    // 国密TLS配置
    isGM     bool             // 监听器类型
    mtx      sync.RWMutex
    handlers map[string]*protocolHandler
    ctx      context.Context
    done     context.CancelFunc
    sock     net.Listener
}
```

#### 连接包装器
```go
// 国密TLS服务器连接包装器
type GMServerConnection struct {
    detail *transport.ConnectionDetail
    Conn   *gmtls.Conn
}

// 实现 transport.Conn 接口
func (c *GMServerConnection) Read(b []byte) (n int, err error)
func (c *GMServerConnection) Write(b []byte) (n int, err error)
func (c *GMServerConnection) Close() error
// ... 其他接口方法
```

### 3. 工作流程

#### 监听器启动流程
1. **配置检测**: `getOptimalServerTLSConfig()` 检测是否有国密证书
2. **协议选择**: 根据检测结果选择TLS实现
3. **监听器创建**: 创建相应的TLS监听器
4. **接受循环**: 启动对应的连接接受处理循环

#### 连接处理流程
1. **连接接受**: `runAccept()` 或 `runGMAccept()`
2. **握手处理**: 标准TLS或国密TLS握手
3. **协议协商**: ALPN协议选择
4. **连接包装**: 创建适当的连接包装器
5. **回调处理**: 调用用户定义的接受函数

## 日志输出

### 成功启动日志
```
# 国密TLS监听器
DEBUG using GM TLS server configuration
INFO  GM TLS listener started on :8443

# 标准TLS监听器（回退）
DEBUG using standard TLS server configuration  
INFO  TLS listener started on :8443
```

### 连接处理日志
```
# 国密TLS连接
DEBUG GM TLS client requesting protocols = [http/1.1, h2]
DEBUG found GM TLS handler for proto[http/1.1]
DEBUG GM TLS selected protocol = 'http/1.1'

# 标准TLS连接
DEBUG client requesting protocols = [http/1.1, h2]
DEBUG found handler for proto[http/1.1] 
DEBUG selected protocol = 'http/1.1'
```

## 兼容性

### 向后兼容性
- **完全兼容**: 现有代码无需修改
- **透明升级**: 自动检测和选择最佳TLS实现
- **渐进迁移**: 支持混合部署环境

### 性能考虑
- **零开销**: 当未配置国密证书时，性能与原版本相同
- **智能选择**: 仅在检测到国密证书时才加载国密TLS模块
- **连接池**: 每种TLS类型独立管理连接

## 故障排除

### 常见问题

1. **国密证书加载失败**
   ```
   DEBUG failed to load GM server certificate: cert.crt, cert.key
   DEBUG using standard TLS server configuration
   ```
   **解决方案**: 检查证书文件路径和格式

2. **协议协商失败**
   ```
   ERROR no GM TLS handler for requested protocols [unknown]
   ```
   **解决方案**: 检查客户端支持的协议列表

3. **握手失败**
   ```
   ERROR GM TLS handshake failed: handshake failure
   ```
   **解决方案**: 检查客户端是否支持国密TLS协议

### 调试模式

```bash
# 启用详细日志
export LOG_LEVEL=debug

# 强制使用标准TLS（测试回退）
export GMTLS_SERVER_CERT_FILE=""
export GMTLS_SERVER_KEY_FILE=""
```

## 测试建议

### 功能测试
1. **标准TLS回退**: 删除国密证书，确认自动回退到标准TLS
2. **国密TLS连接**: 配置国密证书，测试国密TLS连接
3. **协议协商**: 测试不同ALPN协议的协商过程
4. **并发连接**: 测试高并发场景下的稳定性

### 性能测试
1. **延迟测试**: 比较标准TLS和国密TLS的连接延迟
2. **吞吐量测试**: 测试不同TLS实现的数据传输性能
3. **内存使用**: 监控长时间运行的内存使用情况

## 结论

国密TLS监听器集成提供了完整的服务器端国密支持，与拨号器的国密支持形成了完整的端到端解决方案。通过智能检测和自动回退机制，确保了在各种部署环境下的兼容性和可靠性。

监听器升级遵循了与拨号器相同的设计原则：
- **向后兼容**: 不破坏现有功能
- **智能选择**: 自动选择最佳TLS实现  
- **渐进迁移**: 支持混合环境部署
- **性能优化**: 最小化额外开销

现在，OpenZiti Transport 框架完全支持中国国密TLS标准，可以在需要国密合规的环境中安全部署。
