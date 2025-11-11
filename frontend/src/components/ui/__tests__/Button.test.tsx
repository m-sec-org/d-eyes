import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Button } from '../Button';

describe('Button', () => {
  it('applies variant classes and disabled state', () => {
    render(
      <Button variant="ghost-danger" disabled>
        Delete
      </Button>
    );
    const btn = screen.getByRole('button', { name: 'Delete' });
    expect(btn).toHaveClass('ui-button', 'ui-button--ghost-danger');
    expect(btn).toBeDisabled();
  });

  it('supports block layout', () => {
    render(
      <Button variant="secondary" block>
        Full Width
      </Button>
    );
    const btn = screen.getByRole('button', { name: 'Full Width' });
    expect(btn).toHaveClass('ui-button--block');
  });
});
