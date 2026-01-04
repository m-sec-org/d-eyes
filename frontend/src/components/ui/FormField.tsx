import { Children, cloneElement, isValidElement, useId } from 'react';
import type { ReactElement, ReactNode } from 'react';
import { cn } from '@/utils/cn';

interface FormFieldProps {
  label?: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  inline?: boolean;
  children: ReactNode;
  htmlFor?: string;
  className?: string;
}

const CONTROL_TAGS = new Set(['input', 'select', 'textarea']);
const CONTROL_COMPONENT_NAMES = new Set(['Checkbox', 'Select', 'TextInput', 'Textarea']);

function resolveElementName(type: ReactElement['type']): string | undefined {
  if (typeof type === 'string') return type;
  if (typeof type === 'function') return type.displayName || type.name;
  if (type && typeof type === 'object') {
    const candidate = type as any;
    return candidate.displayName || candidate.render?.displayName || candidate.render?.name;
  }
  return undefined;
}

function isFormControlElement(element: ReactElement): boolean {
  if (typeof element.type === 'string') return CONTROL_TAGS.has(element.type);
  const name = resolveElementName(element.type);
  return typeof name === 'string' && CONTROL_COMPONENT_NAMES.has(name);
}

function mergeAriaDescribedBy(existing: unknown, nextId: string | undefined): string | undefined {
  const existingValue = typeof existing === 'string' ? existing.trim() : '';
  const tokens = existingValue.split(/\s+/).filter(Boolean);
  if (nextId) tokens.push(nextId);
  const unique = Array.from(new Set(tokens));
  return unique.join(' ').trim() || undefined;
}

function scanControls(node: ReactNode) {
  let count = 0;
  let firstControlId: string | undefined;

  const visit = (child: ReactNode) => {
    if (count >= 2) return;
    if (!isValidElement(child)) return;

    if (isFormControlElement(child)) {
      count += 1;
      if (count === 1) {
        const idProp = (child.props as any)?.id;
        if (typeof idProp === 'string' && idProp.trim() !== '') {
          firstControlId = idProp.trim();
        }
      }
    }

    const nestedChildren = (child.props as any)?.children;
    if (nestedChildren) {
      Children.forEach(nestedChildren, visit);
    }
  };

  Children.forEach(node, visit);
  return { count, firstControlId };
}

function injectFieldControlA11y(
  node: ReactNode,
  options: { describedById?: string; controlId?: string; forceControlId: boolean }
): ReactNode {
  const state = { assignedControlId: false };

  const enhance = (child: ReactNode): ReactNode => {
    if (!isValidElement(child)) return child;

    const element = child as ReactElement;
    const elementIsControl = isFormControlElement(element);

    const nextProps: Record<string, unknown> = {};
    let changed = false;

    if (elementIsControl && options.describedById) {
      const mergedDescribedBy = mergeAriaDescribedBy((element.props as any)['aria-describedby'], options.describedById);
      if (mergedDescribedBy !== (element.props as any)['aria-describedby']) {
        nextProps['aria-describedby'] = mergedDescribedBy;
        changed = true;
      }
    }

    if (elementIsControl && options.controlId && !state.assignedControlId) {
      const existingId = (element.props as any)?.id;
      const hasExistingId = typeof existingId === 'string' && existingId.trim() !== '';
      if (options.forceControlId || !hasExistingId) {
        nextProps.id = options.controlId;
        changed = true;
      }
      state.assignedControlId = true;
    }

    const originalChildren = (element.props as any)?.children;
    if (originalChildren !== undefined) {
      let childrenChanged = false;
      const nextChildren = Children.map(originalChildren, (grandchild) => {
        const nextGrandchild = enhance(grandchild);
        if (nextGrandchild !== grandchild) {
          childrenChanged = true;
        }
        return nextGrandchild;
      });

      if (childrenChanged) {
        nextProps.children = nextChildren;
        changed = true;
      }
    }

    return changed ? cloneElement(element, nextProps as any) : element;
  };

  return Children.map(node, enhance);
}

export function FormField({ label, hint, error, required, inline, children, htmlFor, className }: FormFieldProps) {
  const reactId = useId();
  const stableId = reactId.replace(/:/g, '');
  const fallbackControlId = `field-${stableId}`;

  const explicitHtmlFor = typeof htmlFor === 'string' && htmlFor.trim() !== '' ? htmlFor.trim() : undefined;
  const { count: controlCount, firstControlId } = scanControls(children);
  const inferredControlId = controlCount === 1 ? firstControlId ?? fallbackControlId : undefined;
  const resolvedControlId = explicitHtmlFor ?? inferredControlId;
  const baseControlId = resolvedControlId ?? fallbackControlId;

  const labelId = label ? `${baseControlId}__label` : undefined;
  const hintId = hint ? `${baseControlId}__hint` : undefined;
  const errorId = error ? `${baseControlId}__error` : undefined;
  const describedById = errorId ?? hintId;

  const renderedChildren =
    describedById || (controlCount === 1 && resolvedControlId)
      ? injectFieldControlA11y(children, {
          describedById,
          controlId: controlCount === 1 ? resolvedControlId : undefined,
          forceControlId: Boolean(explicitHtmlFor) && controlCount === 1,
        })
      : children;

  return (
    <div
      className={cn('ui-field', inline && 'ui-field--inline', className)}
      role={label && !resolvedControlId ? 'group' : undefined}
      aria-labelledby={label && !resolvedControlId ? labelId : undefined}
      aria-describedby={label && !resolvedControlId ? describedById : undefined}
    >
      {label &&
        (resolvedControlId ? (
          <label className="ui-field__label" htmlFor={resolvedControlId} id={labelId}>
            {label}
            {required && <span aria-hidden="true">*</span>}
          </label>
        ) : (
          <span className="ui-field__label" id={labelId}>
            {label}
            {required && <span aria-hidden="true">*</span>}
          </span>
        ))}
      {renderedChildren}
      {error ? (
        <span className="ui-field__error" id={errorId}>
          {error}
        </span>
      ) : hint ? (
        <span className="ui-field__hint" id={hintId}>
          {hint}
        </span>
      ) : null}
    </div>
  );
}
