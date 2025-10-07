import { cn } from "@/lib/utils";

export interface LabelProps extends React.LabelHTMLAttributes<HTMLLabelElement> {}

export const Label = ({ className, ...props }: LabelProps) => (
  <label className={cn("text-sm font-medium text-slate-700", className)} {...props} />
);
