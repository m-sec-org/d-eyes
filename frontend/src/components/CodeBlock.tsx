import './CodeBlock.css';
import { CopyOutlined, CheckOutlined } from '@ant-design/icons';
import { Button, Tooltip } from 'antd';
import { useMemo, useState } from 'react';

interface CodeBlockProps {
  value: unknown;
  title?: string;
  language?: string;
  allowCopy?: boolean;
  maxHeight?: number;
  className?: string;
  ['data-testid']?: string;
}

function formatValue(value: unknown, language?: string) {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) {
    return language === 'json' ? '{}' : '';
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function CodeBlock({
  value,
  title,
  language = 'json',
  allowCopy = true,
  maxHeight = 320,
  className,
  'data-testid': dataTestId,
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const formatted = useMemo(() => formatValue(value, language), [language, value]);

  const handleCopy = async () => {
    if (!allowCopy) return;
    if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) {
      return;
    }
    try {
      await navigator.clipboard.writeText(formatted);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className={`code-block ${className ?? ''}`} data-language={language} data-testid={dataTestId}>
      <div className="code-block__header">
        {title && <span className="code-block__title">{title}</span>}
        {allowCopy && (
          <Tooltip title={copied ? '已复制' : '复制'}>
            <Button
              size="small"
              type="text"
              icon={copied ? <CheckOutlined /> : <CopyOutlined />}
              onClick={handleCopy}
              aria-label="复制代码块内容"
            />
          </Tooltip>
        )}
      </div>
      <pre className="code-block__pre" style={{ maxHeight }} tabIndex={0}>
        {formatted}
      </pre>
    </div>
  );
}
