import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { api, Agent } from '@/api/client'
import { formatBytes, formatSpeed, timeAgo } from '@/lib/utils'
import { Server, Wifi, WifiOff, RefreshCw, Activity, ArrowUpDown, TrendingUp, Download, Upload } from 'lucide-react'

export function AgentsPage() {
  const { data: agents, isLoading, refetch } = useQuery({
    queryKey: ['agents'],
    queryFn: api.getAgents,
    refetchInterval: 5000,
  })

  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: api.getStats,
    refetchInterval: 1000,
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  const onlineCount = agents?.filter(a => a.online).length || 0
  const totalCount = agents?.length || 0

  return (
    <div className="space-y-6">
      {/* Traffic Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 stagger-children">
        <Card className="bg-gradient-to-br from-teal-500/10 to-teal-600/5 border-teal-500/20">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-teal-400/80">总上传流量</p>
                <p className="text-2xl font-bold text-teal-400">{formatBytes(stats?.txBytes || 0)}</p>
                <p className="text-xs text-teal-400/60 mt-1">
                  <TrendingUp className="w-3 h-3 inline mr-1" />
                  {formatSpeed(stats?.txSpeed || 0)}
                </p>
              </div>
              <div className="w-12 h-12 rounded-full bg-teal-500/20 flex items-center justify-center">
                <Upload className="w-6 h-6 text-teal-400" />
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-blue-400/80">总下载流量</p>
                <p className="text-2xl font-bold text-blue-400">{formatBytes(stats?.rxBytes || 0)}</p>
                <p className="text-xs text-blue-400/60 mt-1">
                  <TrendingUp className="w-3 h-3 inline mr-1" />
                  {formatSpeed(stats?.rxSpeed || 0)}
                </p>
              </div>
              <div className="w-12 h-12 rounded-full bg-blue-500/20 flex items-center justify-center">
                <Download className="w-6 h-6 text-blue-400" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-border/50">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">在线 Agents</p>
                <p className="text-2xl font-bold text-primary">{onlineCount}</p>
                <p className="text-xs text-muted-foreground mt-1">共 {totalCount} 个</p>
              </div>
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                <Wifi className="w-6 h-6 text-primary" />
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-card/50 border-border/50">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">活跃隧道</p>
                <p className="text-2xl font-bold text-accent">
                  {agents?.reduce((acc, a) => acc + a.activeTunnels, 0) || 0}
                </p>
                <p className="text-xs text-muted-foreground mt-1">{stats?.totalRules || 0} 条规则</p>
              </div>
              <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center">
                <ArrowUpDown className="w-6 h-6 text-accent" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Agents List */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-lg">Agents 列表</CardTitle>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-2" />
            刷新
          </Button>
        </CardHeader>
        <CardContent>
          {agents && agents.length > 0 ? (
            <div className="space-y-3">
              {agents.map((agent) => (
                <AgentCard key={agent.id} agent={agent} />
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-muted-foreground">
              <Server className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>暂无 Agent 连接</p>
              <p className="text-sm mt-2">运行 Agent 客户端连接到此服务器</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function AgentCard({ agent }: { agent: Agent }) {
  return (
    <div className="flex items-center justify-between p-4 rounded-lg border border-border/50 bg-background/50 hover:bg-background/80 transition-colors">
      <div className="flex items-center gap-4">
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
          agent.online ? 'bg-primary/10' : 'bg-muted'
        }`}>
          {agent.online ? (
            <Wifi className="w-5 h-5 text-primary" />
          ) : (
            <WifiOff className="w-5 h-5 text-muted-foreground" />
          )}
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-medium">{agent.name}</span>
            <Badge variant={agent.online ? 'success' : 'secondary'}>
              {agent.online ? '在线' : '离线'}
            </Badge>
          </div>
          <div className="flex items-center gap-3 text-sm text-muted-foreground mt-1">
            <span className="font-mono text-xs">{agent.id.slice(0, 8)}</span>
            <span>{agent.ip}</span>
            {agent.lastSeen && (
              <span>最后活动: {timeAgo(new Date(agent.lastSeen))}</span>
            )}
          </div>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <div className="text-right">
          <div className="flex items-center gap-2 text-sm">
            <Activity className="w-4 h-4 text-muted-foreground" />
            <span>{agent.activeTunnels} 隧道</span>
          </div>
          <div className="text-xs text-muted-foreground mt-1">
            ↑ {formatBytes(agent.txBytes)} / ↓ {formatBytes(agent.rxBytes)}
          </div>
        </div>
      </div>
    </div>
  )
}

