import { useMemo, useState } from "react";
import { Segmented } from "antd";
import { useTheme } from "../../hooks/useTheme";
import type { AuthSession } from "@/services/types";

interface HeaderProps {
  onCommandPalette: () => void;
  user?: AuthSession["user"];
  paletteOpen?: boolean;
}

const environments = ["Prod", "Stage", "Dev"];

export function Header({ onCommandPalette, user, paletteOpen = false }: HeaderProps) {
  const { theme, toggleTheme } = useTheme();
  const [activeEnvironment, setActiveEnvironment] = useState(environments[0]);

  const envOptions = useMemo(
    () => environments.map((env) => ({ label: env, value: env })),
    []
  );

  return (
    <header className="app-header">
      <div className="brand">
        <div className="logo" aria-hidden="true">
          ◇
        </div>
        <div>
          <div className="brand-title">D-Eyes</div>
          <div className="brand-subtitle">Unified SecOps Console</div>
        </div>
      </div>
      <div className="header-actions">
        <button
          type="button"
          className="command-trigger"
          onClick={onCommandPalette}
          aria-haspopup="dialog"
          aria-expanded={paletteOpen}
          aria-controls="command-palette-panel"
        >
          ⌘K / Ctrl+K
        </button>
        <div className="env-switcher" aria-label="环境切换">
          <Segmented
            size="small"
            options={envOptions}
            value={activeEnvironment}
            onChange={(value) => setActiveEnvironment(String(value))}
            aria-label="环境选择器"
          />
        </div>
        <button type="button" className="icon-button" onClick={toggleTheme} aria-label="Toggle theme">
          {theme === "dark" ? "🌙" : "☀️"}
        </button>
        <button type="button" className="profile-button">
          <span className="avatar">{(user?.display_name ?? "OP").slice(0, 2).toUpperCase()}</span>
          <span className="profile-meta">
            <strong>{user?.display_name ?? user?.username ?? "未登录"}</strong>
            <small>{user?.role ?? "visitor"}</small>
          </span>
        </button>
      </div>
    </header>
  );
}
