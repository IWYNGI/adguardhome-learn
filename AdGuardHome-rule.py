import re

def normalize_rule(rule: str) -> str:
    """
    标准化 AdGuard 白名单规则：
    - 去掉修饰符部分
    - 统一为 @@|域名^$important 形式
    - 转小写
    - 对于符合规则的域名合并通配符
    """
    # 删除修饰符（从第一个 $ 起到行尾）
    rule = re.sub(r'\$.*$', '', rule)
    
    # 删除末尾符号（^、/、空格）
    rule = re.sub(r'[\^/\s]+$', '', rule)
    
    # 去掉多余空格
    rule = re.sub(r'\s+', ' ', rule)
    
    # 提取域名，处理域名前后的一些符号
    match = re.search(r'@@?(\|\|?)([a-zA-Z0-9.-]+)', rule)
    if match:
        domain = match.group(2).lower()

        # 忽略过长的域名（修改为 100 个字符）
        if len(domain) > 100:
            return None
        
        # 尝试自动合并具有相同前缀的规则
        # 找出具有相同前缀并且后缀为可变部分的规则
        if '.' in domain:
            parts = domain.split('.')
            if len(parts) > 2:
                # 如果域名的第二部分是可能变化的部分（例如 `yaoiflix.*.cc`）
                # 生成带通配符的规则
                prefix = parts[0]
                suffix = '.'.join(parts[1:])
                if len(set([suffix])) > 1:  # 如果后缀部分不同，合并为通配符
                    return f'@@|{prefix}.*.{suffix}^$important'
        
        # 默认处理：统一为 @@|域名^$important 格式
        return f'@@|{domain}^$important'
    return None

def merge_and_deduplicate(input_rules):
    """
    处理输入的规则，去重并优化。
    """
    # 存储标准化后的规则
    unique_rules = set()
    
    for rule in input_rules:
        # 标准化每一条规则
        normalized_rule = normalize_rule(rule)
        if normalized_rule:
            unique_rules.add(normalized_rule)
    
    # 返回排序后的规则
    return sorted(unique_rules)

def process_rules(input_file, output_file):
    """
    读取文件，处理规则并写入输出文件。
    """
    with open(input_file, 'r', encoding='utf-8') as f:
        input_rules = f.readlines()

    # 去除空行和多余的空格
    input_rules = [rule.strip() for rule in input_rules if rule.strip()]

    # 合并、去重并排序规则
    processed_rules = merge_and_deduplicate(input_rules)

    # 写入到输出文件
    with open(output_file, 'w', encoding='utf-8') as f:
        for rule in processed_rules:
            f.write(f"{rule}\n")

    # 输出规则行数
    print(f"输出规则行数: {len(processed_rules)}")

# 示例输入和输出文件
input_file = 'rules.txt'
output_file = 'rules_clean.txt'

# 处理规则
process_rules(input_file, output_file)
