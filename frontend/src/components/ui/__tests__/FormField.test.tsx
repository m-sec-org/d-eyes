import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { FormField } from '../FormField';
import { Checkbox } from '../Checkbox';
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
    const input = screen.getByRole('textbox', { name: '端口范围' });
    const describedBy = input.getAttribute('aria-describedby');
    expect(describedBy).toBeTruthy();
    expect(describedBy).toContain('__error');
    expect(document.getElementById(describedBy!)).toHaveTextContent('端口范围非法');
  });

  it('injects aria-describedby into multiple child controls', () => {
    render(
      <FormField label="时间范围" hint="输入开始与结束">
        <>
          <TextInput aria-label="Start" />
          <TextInput aria-label="End" aria-describedby="existing-desc" />
        </>
      </FormField>
    );

    const hint = screen.getByText('输入开始与结束');
    const hintId = hint.getAttribute('id');
    expect(hintId).toBeTruthy();

    const group = screen.getByRole('group', { name: '时间范围' });
    expect(group).toHaveAttribute('aria-describedby', hintId);

    const startInput = screen.getByRole('textbox', { name: 'Start' });
    expect(startInput.getAttribute('aria-describedby')).toContain(hintId);

    const endInput = screen.getByRole('textbox', { name: 'End' });
    const endDescribedBy = endInput.getAttribute('aria-describedby');
    expect(endDescribedBy).toContain('existing-desc');
    expect(endDescribedBy).toContain(hintId);
  });

  it('associates nested child control with label and error', () => {
    render(
      <FormField label="范围" error="范围非法">
        <div>
          <TextInput />
        </div>
      </FormField>
    );

    const input = screen.getByRole('textbox', { name: '范围' });
    const error = screen.getByText('范围非法');
    const errorId = error.getAttribute('id');

    expect(errorId).toBeTruthy();
    expect(input.getAttribute('aria-describedby')).toContain(errorId);
  });

  it('propagates describedby to Checkbox input', () => {
    render(
      <FormField label="执行审批" error="需要确认已获得 memscan 执行审批">
        <Checkbox checked={false} onChange={() => undefined} label="已获得 memscan 执行审批" />
      </FormField>
    );

    const checkbox = screen.getByRole('checkbox');
    const describedBy = checkbox.getAttribute('aria-describedby');
    expect(describedBy).toBeTruthy();
    expect(describedBy).toContain('__error');
  });
});
