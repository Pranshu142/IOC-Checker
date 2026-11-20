import { cn } from '@/lib/utils';

const Table = ({ className, ...p }) => <table data-slot="table" className={cn('w-full caption-bottom text-sm', className)} {...p} />;
const TableHeader = ({ className, ...p }) => <thead className={cn('[&_tr]:border-b', className)} {...p} />;
const TableBody = ({ className, ...p }) => <tbody className={cn('[&_tr:last-child]:border-0', className)} {...p} />;
const TableRow = ({ className, ...p }) => <tr className={cn('border-b transition-colors hover:bg-muted/50', className)} {...p} />;
const TableHead = ({ className, ...p }) => (
  <th className={cn('h-9 px-3 text-left align-middle text-xs font-medium text-muted-foreground', className)} {...p} />
);
const TableCell = ({ className, ...p }) => <td className={cn('px-3 py-2 align-middle', className)} {...p} />;

export { Table, TableHeader, TableBody, TableRow, TableHead, TableCell };
