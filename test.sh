#!/bin/bash

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
    echo -e "${CYAN}NatSvr 集成测试工具${NC}"
    echo ""
    echo "用法: $0 <命令> [选项]"
    echo ""
    echo -e "${GREEN}命令:${NC}"
    echo "  full                 运行完整集成测试 (所有 4 种模式)"
    echo "  mode <模式名>        测试单个模式"
    echo "  ratelimit [MB/s]     运行限速测试 (默认 1 MB/s)"
    echo "  list                 列出可用的测试模式"
    echo "  quick                快速连接测试"
    echo "  benchmark            性能基准测试"
    echo "  unit                 运行单元测试"
    echo "  build                编译测试工具"
    echo ""
    echo -e "${GREEN}模式名称:${NC}"
    echo "  remote / 1           Cloud 监听 -> Agent -> TestServer"
    echo "  cloud-self / 2       Cloud 监听 -> TestServer (直连)"
    echo "  agent-cloud / 3      Agent 监听 -> Cloud -> TestServer"
    echo "  p2p / 4              Agent1 监听 -> Cloud -> Agent2 -> TestServer"
    echo ""
    echo -e "${GREEN}选项:${NC}"
    echo "  -server <地址>       指定外部 Cloud 服务器 (例如: localhost:1880)"
    echo "  -token <令牌>        指定认证令牌"
    echo "  -json                保存 JSON 报告"
    echo "  -markdown            保存 Markdown 报告"
    echo "  -skip-cleanup        测试后不清理进程"
    echo ""
    echo -e "${GREEN}示例:${NC}"
    echo "  $0 full                                    # 运行所有测试"
    echo "  $0 mode remote                             # 测试 remote 模式"
    echo "  $0 mode p2p -json -markdown                # 测试 P2P 并保存报告"
    echo "  $0 ratelimit                               # 测试 1 MB/s 限速"
    echo "  $0 ratelimit 5                             # 测试 5 MB/s 限速"
    echo "  $0 full -server localhost:1880 -token dev-token  # 使用外部服务器"
    echo ""
}

run_ratelimit_test() {
    local rate="${1:-1.0}"
    shift 2>/dev/null || true
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  NatSvr 限速测试: ${rate} MB/s${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    cleanup_processes
    
    go run ./cmd/integration-test -ratelimit -ratelimit-mbps "$rate" "$@"
}

cleanup_processes() {
    echo -e "${YELLOW}清理测试进程...${NC}"
    # 清理可能存在的测试进程 (使用测试端口 11880)
    lsof -ti:11880 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:12001 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:12002 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:12003 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:12004 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:19001 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:19002 2>/dev/null | xargs kill -9 2>/dev/null || true
    rm -f /tmp/natsvr-test.db 2>/dev/null || true
    sleep 1
}

build_test_tool() {
    echo -e "${BLUE}编译测试工具...${NC}"
    go build -o bin/integration-test ./cmd/integration-test
    echo -e "${GREEN}编译完成: bin/integration-test${NC}"
}

run_full_test() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  NatSvr 完整集成测试${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # 清理可能存在的测试进程
    cleanup_processes
    
    # 编译并运行
    go run ./cmd/integration-test "$@"
}

run_mode_test() {
    local mode="$1"
    shift
    
    if [ -z "$mode" ]; then
        echo -e "${RED}错误: 请指定测试模式${NC}"
        echo ""
        echo "可用模式: remote, cloud-self, agent-cloud, p2p"
        echo "或使用数字: 1, 2, 3, 4"
        exit 1
    fi
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  NatSvr 单模式测试: ${mode}${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    cleanup_processes
    
    go run ./cmd/integration-test -mode "$mode" "$@"
}

list_modes() {
    go run ./cmd/integration-test -list
}

run_quick_test() {
    local server="${1:-}"
    local token="${2:-}"
    
    if [ -z "$server" ] || [ -z "$token" ]; then
        echo -e "${YELLOW}用法: $0 quick <server> <token>${NC}"
        echo "示例: $0 quick localhost:1880 dev-token"
        exit 1
    fi
    
    echo -e "${BLUE}快速测试: $server${NC}"
    go run ./cmd/integration-test -server "$server" -token "$token" -mode remote
}

run_benchmark() {
    local server="${1:-}"
    local token="${2:-}"
    
    if [ -z "$server" ] || [ -z "$token" ]; then
        echo -e "${YELLOW}用法: $0 benchmark <server> <token>${NC}"
        echo "示例: $0 benchmark localhost:1880 dev-token"
        exit 1
    fi
    
    echo -e "${BLUE}性能基准测试: $server${NC}"
    go run ./cmd/integration-test -server "$server" -token "$token" -json -markdown
}

run_unit_test() {
    echo -e "${BLUE}运行单元测试...${NC}"
    go test -short ./...
    echo -e "${GREEN}单元测试完成${NC}"
}

# 主入口
case "${1:-}" in
    full)
        shift
        run_full_test "$@"
        ;;
    mode)
        shift
        run_mode_test "$@"
        ;;
    ratelimit)
        shift
        run_ratelimit_test "$@"
        ;;
    list)
        list_modes
        ;;
    quick)
        shift
        run_quick_test "$@"
        ;;
    benchmark)
        shift
        run_benchmark "$@"
        ;;
    unit)
        run_unit_test
        ;;
    build)
        build_test_tool
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
