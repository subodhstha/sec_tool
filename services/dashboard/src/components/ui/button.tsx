import * as React from "react";
import { cn } from "@/lib/utils";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "outline" | "ghost" | "danger";
  size?: "default" | "sm" | "lg" | "icon";
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap rounded-xl font-medium transition-all focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-brand-500 disabled:pointer-events-none disabled:opacity-50",
          {
            "bg-brand-500 text-white hover:bg-brand-400 shadow-[0_0_15px_rgba(99,102,241,0.3)]": variant === "default",
            "border border-white/10 bg-transparent hover:bg-white/5 text-zinc-300": variant === "outline",
            "hover:bg-white/5 text-zinc-300 hover:text-white": variant === "ghost",
            "bg-accent-rose/10 text-accent-rose hover:bg-accent-rose/20 border border-accent-rose/20": variant === "danger",
            "h-10 px-5 py-2.5 text-sm": size === "default",
            "h-8 rounded-lg px-3 text-xs": size === "sm",
            "h-12 px-8 text-base": size === "lg",
            "h-10 w-10": size === "icon",
          },
          className
        )}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button };
