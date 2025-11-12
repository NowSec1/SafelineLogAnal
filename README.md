# SafelineLogAnal

该项目提供一个简单的自动化工具，用于分析 Safeline Web 攻击告警导出的 Excel 文件，识别真实攻击 payload，并将疑似误报或正常业务的告警导出为新的 Excel 文件。

## 功能概述

- 首选分析 Excel `AU` 列（列名 `payload`）中的攻击负载内容。
- 如果 `payload` 列不存在，则回退分析 `C` 列（列名 `website`）中的 URL。
- 通过内置的多种攻击特征（SQL 注入、XSS、命令执行、目录遍历等）识别真实攻击。
- 为每条告警生成分析结果，包括是否为恶意以及命中的特征描述。
- 自动导出疑似误报/正常业务的告警到新的 Excel 文件，便于人工复核。

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用示例

```bash
python -m safeline_log_anal.cli input.xlsx --output suspected_false_positives.xlsx
```

可选参数：

- `--sheet`：指定需要分析的工作表名称或索引（默认值为 `0`，即第一个工作表）。
- `--payload-column`：指定包含攻击负载的列名（默认 `payload`）。
- `--fallback-column`：当 payload 列不存在时，指定用于分析的回退列名（默认 `website`）。

运行后，工具会在命令行输出分析统计信息，并将判定为“非恶意”的告警保存到新的 Excel 文件中。

## 在代码中使用

```python
import pandas as pd
from safeline_log_anal import analyze_alerts

# 读取 Excel 数据
df = pd.read_excel("input.xlsx")

# 得到带分析结果的完整数据以及疑似误报的数据
annotated_df, benign_df = analyze_alerts(df)

# 将疑似误报导出
benign_df.to_excel("suspected_false_positives.xlsx", index=False)
```

## 测试

```bash
python -m unittest
```
