import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { FormField } from '../FormField';
import { TextInput } from '../TextInput';

describe('FormField', () => {
  it('renders label, hint and child control', () => {
    render(
      <FormField label="Asset Name" hint="对外可见别名">
        <TextInput placeholder="ops-core" />
      </FormField>
    );

    expect(screen.getByText('Asset Name')).toBeInTheDocument();
    expect(screen.getByText('对外可见别名')).toHaveClass('ui-field__hint');
    expect(screen.getByPlaceholderText('ops-core')).toBeInTheDocument();
  });

  it('shows error instead of hint when provided', () => {
    render(
      <FormField label="端口范围" hint="1-65535" error="端口范围非法">
        <TextInput type="text" />
      </FormField>
    );

    expect(screen.queryByText('1-65535')).not.toBeInTheDocument();
    expect(screen.getByText('端口范围非法')).toHaveClass('ui-field__error');
  });
});
