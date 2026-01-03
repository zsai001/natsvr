#!/bin/bash

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
CLOUD_ADDR=":1880"
DEV_TOKEN="dev-token"
AGENT_NAME="dev-agent"

# PID 文件
CLOUD_PID=""
AGENT_PID=""
FRONTEND_PID=""

cleanup() {
    echo -e "\n${YELLOW}正在停止服务...${NC}"
    if [ -n "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
        kill "$FRONTEND_PID" 2>/dev/null || true
        echo -e "${GREEN}Frontend 已停止${NC}"
    fi
    if [ -n "$CLOUD_PID" ] && kill -0 "$CLOUD_PID" 2>/dev/null; then
        kill "$CLOUD_PID" 2>/dev/null || true
        echo -e "${GREEN}Cloud 已停止${NC}"
    fi
    if [ -n "$AGENT_PID" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
        echo -e "${GREEN}Agent 已停止${NC}"
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

prepare_dist() {
    mkdir -p cmd/cloud/dist
    echo '<!DOCTYPE html><html><body><h1>Development Mode</h1><p>Frontend dev server: npm run dev in web/</p></body></html>' > cmd/cloud/dist/index.html
}

start_cloud() {
    echo -e "${BLUE}启动 Cloud 服务...${NC}"
    go run ./cmd/cloud -addr "$CLOUD_ADDR" -token "$DEV_TOKEN" -dev &
    CLOUD_PID=$!
    echo -e "${GREEN}Cloud PID: $CLOUD_PID${NC}"
}

start_agent() {
    echo -e "${BLUE}启动 Agent 服务...${NC}"
    sleep 2  # 等待 Cloud 启动
    go run ./cmd/agent -server "ws://localhost${CLOUD_ADDR}/ws" -token "$DEV_TOKEN" -name "$AGENT_NAME" &
    AGENT_PID=$!
    echo -e "${GREEN}Agent PID: $AGENT_PID${NC}"
}

start_frontend() {
    echo -e "${BLUE}启动前端开发服务器...${NC}"
    (cd web && npm run dev) &
    FRONTEND_PID=$!
    echo -e "${GREEN}Frontend PID: $FRONTEND_PID${NC}"
}

dev() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  NatSvr 开发模式${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "${YELLOW}前端地址: http://localhost:5173 (Vite HMR)${NC}"
    echo -e "${YELLOW}云端地址: http://localhost${CLOUD_ADDR} (代理到 Vite)${NC}"
    echo -e "${YELLOW}Token: ${DEV_TOKEN}${NC}"
    echo -e "${YELLOW}Agent 名称: ${AGENT_NAME}${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""

    prepare_dist
    start_frontend
    start_cloud
    start_agent

    echo ""
    echo -e "${GREEN}服务已启动，按 Ctrl+C 停止${NC}"
    echo ""

    # 等待子进程
    wait
}

dev_cloud() {
    echo -e "${BLUE}仅启动 Cloud 服务...${NC}"
    prepare_dist
    go run ./cmd/cloud -addr "$CLOUD_ADDR" -token "$DEV_TOKEN" -dev
}

dev_agent() {
    echo -e "${BLUE}仅启动 Agent 服务...${NC}"
    go run ./cmd/agent -server "ws://localhost${CLOUD_ADDR}/ws" -token "$DEV_TOKEN" -name "$AGENT_NAME"
}

dev_frontend() {
    echo -e "${BLUE}启动前端开发服务器...${NC}"
    cd web && npm run dev
}

build() {
    echo -e "${BLUE}构建项目...${NC}"
    
    # 构建前端
    echo -e "${YELLOW}构建前端...${NC}"
    cd web && npm install && npm run build
    cd ..
    
    # 复制前端
    echo -e "${YELLOW}复制前端资源...${NC}"
    rm -rf cmd/cloud/dist
    cp -r web/dist cmd/cloud/dist
    
    # 构建后端
    echo -e "${YELLOW}构建后端...${NC}"
    CGO_ENABLED=0 go build -o bin/cloud ./cmd/cloud
    CGO_ENABLED=0 go build -o bin/agent ./cmd/agent
    
    echo -e "${GREEN}构建完成!${NC}"
    echo -e "  bin/cloud"
    echo -e "  bin/agent"
}

build_linux() {
    echo -e "${BLUE}构建 Linux 版本...${NC}"
    
    # 构建前端
    echo -e "${YELLOW}构建前端...${NC}"
    cd web && npm install && npm run build
    cd ..
    
    # 复制前端
    echo -e "${YELLOW}复制前端资源...${NC}"
    rm -rf cmd/cloud/dist
    cp -r web/dist cmd/cloud/dist
    
    # 构建 Linux amd64 后端
    echo -e "${YELLOW}构建 Linux amd64 后端...${NC}"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/cloud-linux-amd64 ./cmd/cloud
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/agent-linux-amd64 ./cmd/agent
    
    echo -e "${GREEN}构建完成!${NC}"
    echo -e "  bin/cloud-linux-amd64"
    echo -e "  bin/agent-linux-amd64"
}

clean() {
    echo -e "${YELLOW}清理构建产物...${NC}"
    rm -rf bin/
    rm -rf web/dist/
    rm -rf cmd/cloud/dist/
    echo -e "${GREEN}清理完成${NC}"
}

usage() {
    echo "用法: $0 <命令>"
    echo ""
    echo "命令:"
    echo "  dev          启动开发模式 (Frontend + Cloud + Agent)"
    echo "  cloud        仅启动 Cloud"
    echo "  agent        仅启动 Agent"
    echo "  frontend     仅启动前端开发服务器"
    echo "  build        构建项目"
    echo "  build-linux  构建 Linux amd64 版本"
    echo "  clean        清理构建产物"
    echo ""
}

case "${1:-}" in
    dev)
        dev
        ;;
    cloud)
        dev_cloud
        ;;
    agent)
        dev_agent
        ;;
    frontend)
        dev_frontend
        ;;
    build)
        build
        ;;
    build-linux)
        build_linux
        ;;
    clean)
        clean
        ;;
    *)
        usage
        exit 1
        ;;
esac

