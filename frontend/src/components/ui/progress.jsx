import * as ProgressPrimitive from '@radix-ui/react-progress';
import { cn } from '@/lib/utils';

function Progress({ className, value, ...props }) {
  return (
    <ProgressPrimitive.Root
      data-slot="progress"
      value={value}
      className={cn('relative h-1.5 w-full overflow-hidden rounded-full bg-primary/10', className)}
      {...props}
    >
      <ProgressPrimitive.Indicator className="h-full bg-primary transition-all" style={{ width: `${value || 0}%` }} />
    </ProgressPrimitive.Root>
  );
}

export { Progress };
