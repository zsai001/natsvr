import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AgentsPage } from '@/pages/AgentsPage'
import { ForwardingPage } from '@/pages/ForwardingPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { Button } from '@/components/ui/button'
import { useTheme } from '@/hooks/useTheme'
import { Network, ArrowRightLeft, Settings, Activity, Sun, Moon } from 'lucide-react'

function App() {
  const { theme, toggleTheme } = useTheme()

  return (
    <div className="min-h-screen bg-background grid-background">
      {/* Header */}
      <header className="border-b border-border/50 backdrop-blur-sm sticky top-0 z-40 bg-background/80">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary to-accent flex items-center justify-center">
                <Network className="w-5 h-5 text-white dark:text-background" />
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-tight">natsvr</h1>
                <p className="text-xs text-muted-foreground">内网穿透控制面板</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 dark:bg-teal-400/10 border border-emerald-500/20 dark:border-teal-400/20">
                <Activity className="w-3 h-3 text-emerald-500 dark:text-teal-400 animate-pulse-glow" />
                <span className="text-xs text-emerald-600 dark:text-teal-400 font-medium">系统运行中</span>
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={toggleTheme}
                className="rounded-full"
                title={theme === 'dark' ? '切换到浅色模式' : '切换到深色模式'}
              >
                {theme === 'dark' ? (
                  <Sun className="w-5 h-5 text-yellow-400" />
                ) : (
                  <Moon className="w-5 h-5 text-slate-600" />
                )}
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        <Tabs defaultValue="agents" className="space-y-6">
          <TabsList className="bg-card/50 border border-border/50 p-1">
            <TabsTrigger value="agents" className="gap-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              <Network className="w-4 h-4" />
              Agents
            </TabsTrigger>
            <TabsTrigger value="forwarding" className="gap-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              <ArrowRightLeft className="w-4 h-4" />
              端口转发
            </TabsTrigger>
            <TabsTrigger value="settings" className="gap-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              <Settings className="w-4 h-4" />
              设置
            </TabsTrigger>
          </TabsList>

          <TabsContent value="agents" className="animate-fade-in">
            <AgentsPage />
          </TabsContent>
          
          <TabsContent value="forwarding" className="animate-fade-in">
            <ForwardingPage />
          </TabsContent>
          
          <TabsContent value="settings" className="animate-fade-in">
            <SettingsPage />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  )
}

export default App

