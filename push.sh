#!/bin/bash

# Push脚本 - 更新list.meta.yml并强制推送
set -e

echo "开始执行push脚本..."

# 1. 下载最新的list.meta.yml文件
echo "正在下载最新的list.meta.yml文件..."
curl -o list.meta.yml https://github.com/eshao731/AutoMergePublicNodes/raw/refs/heads/master/list.meta.yml

if [ $? -eq 0 ]; then
    echo "✓ list.meta.yml文件下载成功"
else
    echo "✗ 下载list.meta.yml文件失败"
    exit 1
fi

# 2. 添加文件到git暂存区
echo "正在添加文件到git暂存区..."
git add list.meta.yml

# 3. amend提交到最后一次提交
echo "正在执行amend提交..."
if git commit --amend --no-edit; then
    echo "✓ amend提交成功"
else
    echo "✗ amend提交失败，可能没有新的更改"
fi

# 4. 强制推送到远端
echo "正在强制推送到远端..."
git push --force

if [ $? -eq 0 ]; then
    echo "✓ 强制推送成功"
else
    echo "✗ 强制推送失败"
    exit 1
fi

echo "push脚本执行完成！"
