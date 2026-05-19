import { Settings } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent } from '@/components/ui/card';

export default function SettingsPage() {
  return (
    <div className="flex flex-col">
      <TopBar title="Settings" subtitle="Console and platform configuration" />
      <div className="p-6">
        <Card>
          <CardContent className="pt-6">
            <div
              className="flex flex-col items-center gap-3 py-10 text-center"
              aria-label="module-not-configured"
            >
              <Settings className="h-8 w-8 text-muted/40" aria-hidden="true" />
              <p className="text-sm font-medium text-foreground">
                Settings module not yet configured
              </p>
              <p className="max-w-sm text-xs text-muted">
                This module will provide console configuration, tenant-scoped preferences,
                and platform administration settings for authorized operators.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
