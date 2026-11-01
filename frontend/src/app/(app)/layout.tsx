import { ToastProvider } from "@/components/ui";

// Authenticated product + login: the approved dark command-center theme.
export default function AppLayout({ children }: { children: React.ReactNode }) {
  return <div className="theme-app"><ToastProvider>{children}</ToastProvider></div>;
}
