import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { CodeBlock } from '@/components/CodeBlock';

describe('CodeBlock', () => {
  it('formats JSON values and renders pretty output', () => {
    render(<CodeBlock value={{ foo: 'bar' }} allowCopy={false} />);
    expect(screen.getByText(/"foo": "bar"/)).toBeInTheDocument();
  });

  it('copies formatted text to clipboard', async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    render(<CodeBlock value={{ foo: 'bar' }} title="示例" />);
    await user.click(screen.getByLabelText('复制代码块内容'));
    expect(writeText).toHaveBeenCalledWith('{\n  "foo": "bar"\n}');
  });
});
