抽奖结果公布后有人质疑早就能改，因为承诺值里根本没绑定开奖内容，换一份也能验过：承诺必须同时绑定开奖内容和随机盐，盐要足够长并且不得重复使用；打开承诺时必须同时核对盐与内容；同一内容配不同的盐要产生不同承诺；盐不得以明文出现在承诺值里；批量承诺中的每一条都要独立生成并校验。关键不变量是，更换内容或者更换盐都必然导致打开失败，同一输入连续承诺两次得到相同结果。

## 概览

本仓库提供一个基于随机盐的承诺方案，用于在公布结果之前先发布不可更改的承诺值，并在公布之后执行打开校验。

## 接口约定

- `new_salt(entropy) -> str`：生成新的随机盐，entropy 表示随机字节数，返回值至少满足默认盐策略。
- `commit(value, salt) -> str`：生成承诺值。
- `open_commit(value, salt, commitment) -> bool`：用内容与盐打开承诺，成功返回 true，失败返回 false。
- `check_salt(salt, policy) -> bool`：按策略检查盐的长度与字符集。默认策略要求十六进制字符集且最短 16 个字符，策略键为 min_len、max_len、alphabet。
- `check_uniqueness(records) -> list[str]`：records 是包含 salt 键的映射序列，返回重复出现的盐，按字典序排列。
- `domain_separate(label, value) -> str`：把用途标签与值组合成域分离字符串。
- `validate_scheme(policy) -> list[str]`：检查策略并返回问题代码，包括 salt_too_short、no_domain_separation、reversible_commitment。
- `commit_batch(items) -> dict`：items 是包含 id 与 value 的映射序列，返回 id 到 value、salt、commitment 记录的映射。

策略中的 domain_separation 为 true 且 hash 为 sha256、sha3_256 或 blake2s 时，分别视为具备域分离和使用安全摘要。

## 测试

在仓库根目录执行：

```text
python -m pytest tests -q
```

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

