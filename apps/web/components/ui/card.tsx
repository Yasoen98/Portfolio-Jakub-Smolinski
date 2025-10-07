import { cn } from "@/lib/utils";

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {}

export const Card = ({ className, ...props }: CardProps) => (
  <div
    className={cn("rounded-lg border border-slate-200 bg-white p-6 shadow-sm", className)}
    {...props}
  />
);

export const CardHeader = ({ className, ...props }: CardProps) => (
  <div className={cn("mb-4", className)} {...props} />
);

export const CardTitle = ({ className, ...props }: CardProps) => (
  <h3 className={cn("text-lg font-semibold", className)} {...props} />
);

export const CardDescription = ({ className, ...props }: CardProps) => (
  <p className={cn("text-sm text-slate-500", className)} {...props} />
);
