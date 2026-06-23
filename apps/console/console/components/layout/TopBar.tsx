'use client';

import { Bell, Settings } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface TopBarProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}

export function TopBar({ title, subtitle, actions }: TopBarProps) {
  return (
    <header className="flex h-16 shrink-0 items-center justify-between border-b border-border bg-surface px-6">
      <div>
        <h1 className="text-sm font-semibold text-foreground">{title}</h1>
        {subtitle && <p className="text-xs text-muted mt-0.5">{subtitle}</p>}
      </div>

      <div className="flex items-center gap-3">
        {actions}

        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-4 w-4" />
          <Badge
            variant="danger"
            className="absolute -top-1 -right-1 h-4 w-4 p-0 flex items-center justify-center text-[10px] rounded-full"
          >
            2
          </Badge>
        </Button>

        <Button variant="ghost" size="icon">
          <Settings className="h-4 w-4" />
        </Button>

        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold">
          FG
        </div>
      </div>
    </header>
  );
}
