import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { api } from '@/api/client'
import { Copy, Plus, Trash2, Key, RefreshCw, Info } from 'lucide-react'

export function SettingsPage() {
  const queryClient = useQueryClient()
  const [newTokenName, setNewTokenName] = useState('')
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const { data: tokens, isLoading } = useQuery({
    queryKey: ['tokens'],
    queryFn: api.getTokens,
  })

  const { data: version } = useQuery({
    queryKey: ['version'],
    queryFn: api.getVersion,
    staleTime: Infinity, // Version doesn't change during runtime
  })

  const createMutation = useMutation({
    mutationFn: api.createToken,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tokens'] })
      setNewTokenName('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: api.deleteToken,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tokens'] })
    },
  })

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  return (
    <div className="space-y-6 max-w-3xl">
      {/* Token Management */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Key className="w-5 h-5" />
            认证 Token 管理
          </CardTitle>
          <CardDescription>
            管理 Agent 连接认证使用的 Token
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Create Token */}
          <div className="flex gap-2">
            <Input
              placeholder="Token 名称 (例如: production-agent)"
              value={newTokenName}
              onChange={(e) => setNewTokenName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && newTokenName) {
                  createMutation.mutate(newTokenName)
                }
              }}
            />
            <Button
              onClick={() => createMutation.mutate(newTokenName)}
              disabled={!newTokenName || createMutation.isPending}
            >
              <Plus className="w-4 h-4 mr-2" />
              创建
            </Button>
          </div>

          {/* Token List */}
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : tokens && tokens.length > 0 ? (
            <div className="space-y-2">
              {tokens.map((token) => (
                <div
                  key={token.id}
                  className="flex items-center justify-between p-3 rounded-lg border border-border/50 bg-background/50"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded bg-primary/10 flex items-center justify-center">
                      <Key className="w-4 h-4 text-primary" />
                    </div>
                    <div>
                      <p className="font-medium">{token.name}</p>
                      <p className="text-xs text-muted-foreground font-mono">
                        {token.token.slice(0, 8)}...{token.token.slice(-8)}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">
                      {token.usageCount} 次使用
                    </Badge>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => copyToClipboard(token.token, token.id)}
                    >
                      <Copy className={`w-4 h-4 ${copiedId === token.id ? 'text-primary' : ''}`} />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => deleteMutation.mutate(token.id)}
                    >
                      <Trash2 className="w-4 h-4 text-destructive" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Key className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>暂无 Token</p>
              <p className="text-sm mt-2">创建一个 Token 用于 Agent 认证</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Server Info */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Info className="w-5 h-5" />
            服务器信息
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* Version Info Row */}
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Badge variant="outline" className="font-mono">
                Version: {version?.version || 'dev'}
              </Badge>
              <span className="text-muted-foreground">•</span>
              <span className="text-muted-foreground font-mono">
                Commit: {version?.commit || 'unknown'}
              </span>
              <span className="text-muted-foreground">•</span>
              <span className="text-muted-foreground font-mono">
                Branch: {version?.branch || 'unknown'}
              </span>
              <span className="text-muted-foreground">•</span>
              <span className="text-muted-foreground font-mono">
                Built: {version?.buildTime || 'unknown'}
              </span>
            </div>
            
            {/* Endpoints */}
            <div className="grid grid-cols-2 gap-4 pt-2 border-t border-border/50">
              <div>
                <Label className="text-muted-foreground">WebSocket 端点</Label>
                <p className="font-mono text-sm">/ws</p>
              </div>
              <div>
                <Label className="text-muted-foreground">API 端点</Label>
                <p className="font-mono text-sm">/api</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Usage Guide */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader>
          <CardTitle className="text-lg">Agent 连接指南</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              使用以下命令启动 Agent 并连接到此服务器:
            </p>
            <pre className="p-4 rounded-lg bg-background border border-border font-mono text-sm overflow-x-auto">
              <code>./agent -server ws://YOUR_SERVER:8080/ws -token YOUR_TOKEN -name my-agent</code>
            </pre>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

