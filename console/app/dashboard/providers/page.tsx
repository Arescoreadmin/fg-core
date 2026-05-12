import { Package } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent } from '@/components/ui/card';

export default function ProvidersPage() {
  return (
    <div className="flex flex-col">
      <TopBar title="Providers" subtitle="AI provider governance and routing configuration" />
      <div className="p-6">
        <Card>
          <CardContent className="pt-6">
            <div
              className="flex flex-col items-center gap-3 py-10 text-center"
              aria-label="module-not-configured"
            >
              <Package className="h-8 w-8 text-muted/40" aria-hidden="true" />
              <p className="text-sm font-medium text-foreground">
                Providers module not yet configured
              </p>
              <p className="max-w-sm text-xs text-muted">
                This module will provide AI provider governance workflows including provider
                routing rules, classification-based routing, and provider connectivity status.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
