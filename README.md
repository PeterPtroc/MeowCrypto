# MeowCrypto 🐱

一个为群友写的加密工具，旨在将任意文本转换为猫言猫语

## 构建

需要支持c++17

```bash
# 编译
make

# 运行测试
make test

# 清理
make clean
```

## 使用方法

```bash
meowcrypto --mode <encrypt|decrypt> [--key <密钥>] <字符串>
```

### 加密

```bash
# 使用默认密钥加密
./meowcrypto --mode encrypt "Hello World"
>呜嗷~吼嗯嘤呦嘶哼~唔嘶咕呼哼~吼啾呜~嘶咕唔吼~唔~喵喵喵
# 使用自定义密钥加密
./meowcrypto --mode encrypt --key "mykey" "你好世界"
>呜噜~呦吼~哈唔~吼~哼~哼~嗯~嗯~呜唔~嘤~啾~呦~哈嘤咪~吼~嘤~哈喵~喵
```

### 解密

```bash
# 解密猫语
./meowcrypto --mode decrypt "喵呜咪嗷..."

# 使用自定义密钥解密
./meowcrypto --mode decrypt --key "mykey" "喵呜咪嗷..."
```

## 项目结构

```
MeowCrypto/
├── include/
│   └── meow_crypto.h    # api头文件
├── src/
│   ├── main.cpp         # 命令行入口
│   └── meow_crypto.cpp  # 核心实现
├── tests/
│   └── test_meow.cpp    # 单元测试
└── Makefile
```

## 编码原理

1. 压缩：对输入数据进行lz压缩
2. 加密：使用密钥对压缩数据进行异或加密
3. 编码：将二进制数据转换为5-bit编码，映射到32个符号（16 个字符 + `~` 修饰符）（为了增加信息密度，处理时使用gbk，仅输出时使用utf-8
4. 输出：生成utf-8字符串

## 许可证

MIT License
