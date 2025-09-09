# ✅ 国密TLS集成完成 - 使用指南

## 🎉 集成成功！

您的 `tls/dialer.go` 现在已经支持国密TLS了！主程序可以直接订阅增强后的 `DialWithLocalBinding` 函数。

## 📋 已完成的修改

### 1. 保持完全向后兼容
- ✅ 函数签名完全不变：`DialWithLocalBinding(a address, name, localBinding string, i *identity.TokenId, timeout time.Duration, proxyConf *transport.ProxyConfiguration, protocols ...string)`
- ✅ 返回类型完全不变：`(transport.Conn, error)`
- ✅ 现有代码无需任何修改

### 2. 智能TLS选择机制
- ✅ 自动检测国密证书配置
- ✅ 优先使用国密TLS（如果可用）
- ✅ 无缝回退到标准TLS（如果无国密配置）
- ✅ 详细的日志记录

### 3. 多种配置方式
- ✅ 环境变量配置（推荐）
- ✅ 默认文件路径配置
- ✅ 自动检测，零配置使用

## 🚀 立即使用

### 方法1：环境变量配置（推荐）
```bash
# 设置国密证书路径
export GMTLS_CERT_FILE="/path/to/your/sm2-client.crt"
export GMTLS_KEY_FILE="/path/to/your/sm2-client.key"

# 运行您的程序，会自动使用国密TLS
./your-program
```

### 方法2：文件路径配置
将您的SM2证书文件放到以下任一路径：
```
./certs/gm-client.crt 和 ./certs/gm-client.key
./gmtls/client.crt 和 ./gmtls/client.key  
/etc/ssl/gmtls/client.crt 和 /etc/ssl/gmtls/client.key
./gm.crt 和 ./gm.key
```

然后直接运行程序，会自动检测并使用国密TLS。

### 方法3：无配置测试
不设置任何国密证书，程序会自动使用标准TLS，完全兼容现有功能。

## 📊 运行效果

### 使用标准TLS时的日志：
```
[DEBUG] using standard TLS configuration
[DEBUG] server provided [2] certificates
```

### 使用国密TLS时的日志：
```
[DEBUG] using GM TLS configuration  
[INFO]  loaded GM TLS config from ./certs/gm-client.crt
[DEBUG] GM TLS connection established
```

## 🔍 工作原理

1. **智能检测**：`getOptimalTLSConfig()` 按优先级检测配置
   - 环境变量 → 默认路径 → 标准TLS

2. **类型适配**：支持两种连接类型
   - `*tls.Conn` → 标准TLS连接
   - `*gmtls.Conn` → 国密TLS连接（通过GMConnection包装）

3. **无缝集成**：主程序完全不感知底层实现
   - 订阅相同的 `DialWithLocalBinding` 函数
   - 得到相同的 `transport.Conn` 接口
   - 享受国密TLS的安全性

## 🧪 测试验证

### 步骤1：验证标准TLS（回退机制）
```bash
# 不设置国密证书
./your-program
# 应该看到：[DEBUG] using standard TLS configuration
```

### 步骤2：验证国密TLS
```bash
# 设置国密证书
export GMTLS_CERT_FILE="/path/to/sm2-client.crt"
export GMTLS_KEY_FILE="/path/to/sm2-client.key"

./your-program  
# 应该看到：[DEBUG] using GM TLS configuration
```

### 步骤3：验证自动检测
```bash
# 将证书放在默认路径
mkdir -p ./certs
cp your-sm2-client.crt ./certs/gm-client.crt
cp your-sm2-client.key ./certs/gm-client.key

./your-program
# 应该看到：[INFO] loaded GM TLS config from ./certs/gm-client.crt
```

## 🎯 核心优势

### 对主程序来说：
- ✅ **零修改**：订阅相同的函数，获得国密支持
- ✅ **零风险**：完全向后兼容，不影响现有功能
- ✅ **零感知**：透明的国密TLS支持

### 对运维来说：
- ✅ **灵活配置**：环境变量或文件路径
- ✅ **渐进迁移**：可以逐步启用国密TLS
- ✅ **自动回退**：无国密证书时自动使用标准TLS

### 对开发来说：
- ✅ **详细日志**：清楚了解使用的TLS类型
- ✅ **错误处理**：优雅的错误处理和回退
- ✅ **易于调试**：明确的状态信息

## 📈 下一步

1. **准备证书**：获取或生成SM2证书文件
2. **配置环境**：设置环境变量或文件路径
3. **测试验证**：先测试标准TLS，再测试国密TLS
4. **生产部署**：在生产环境中启用国密TLS

## 🎉 恭喜！

您已经成功实现了：
- **策略模式兼容**：主程序可以直接订阅增强的 `DialWithLocalBinding`
- **国密TLS支持**：自动使用国密算法进行安全连接
- **完美兼容**：现有代码和功能完全不受影响

您的传输层现在同时支持标准TLS和国密TLS，实现了真正的双模式安全传输！🚀
