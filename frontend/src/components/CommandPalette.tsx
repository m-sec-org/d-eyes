import { createPortal } from 'react-dom';
import type { CommandItem } from '../hooks/useCommandPalette';

interface CommandPaletteProps {
  open: boolean;
  items: CommandItem[];
  query: string;
  onQueryChange: (value: string) => void;
  onClose: () => void;
  onSelect?: (item: CommandItem) => void;
}

export function CommandPalette({ open, items, query, onQueryChange, onClose, onSelect }: CommandPaletteProps) {
  if (!open || typeof document === 'undefined') return null;

  const titleId = 'command-palette-title';
  const listId = 'command-palette-list';

  return createPortal(
    <div className="command-overlay" role="presentation" data-testid="command-palette-overlay">
      <div
        className="command-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        id="command-palette-panel"
      >
        <div className="sr-only" id={titleId}>
          命令面板
        </div>
        <div className="command-header">
          <label htmlFor="command-search" className="sr-only">
            搜索命令
          </label>
          <input
            id="command-search"
            className="ui-control"
            autoFocus
            value={query}
            placeholder="搜索任务、风险、资产或操作…"
            onChange={(event) => onQueryChange(event.target.value)}
            aria-controls={listId}
          />
          <button type="button" className="icon-button" onClick={onClose} aria-label="关闭命令面板">
            Esc
          </button>
        </div>
        <div className="command-result" role="region" aria-live="polite" aria-label="命令结果">
          {items.length === 0 && <p className="empty">没有匹配项</p>}
          <ul id={listId} role="listbox" aria-label="命令列表">
            {items.map((item) => (
              <li key={item.id} role="option" aria-selected="false">
                <button
                  type="button"
                  className="command-item"
                  onClick={() => onSelect?.(item)}
                  aria-label={item.description ? `${item.label}，${item.description}` : item.label}
                >
                  <div>
                    <div className="command-label">{item.label}</div>
                    {item.description && <div className="command-desc">{item.description}</div>}
                  </div>
                  {item.shortcut && <kbd>{item.shortcut}</kbd>}
                </button>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>,
    document.body
  );
}
