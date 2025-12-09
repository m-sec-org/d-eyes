import { unstableSetRender } from 'antd';
import { createRoot, type Root } from 'react-dom/client';

if (typeof document !== 'undefined') {
  const roots = new WeakMap<Element | DocumentFragment, Root>();

  unstableSetRender((node, container) => {
    const target = container as Element | DocumentFragment;
    let root = roots.get(target);
    if (!root) {
      root = createRoot(target);
      roots.set(target, root);
    }
    root.render(node);

    return async () => {
      const storedRoot = roots.get(target);
      storedRoot?.unmount();
      roots.delete(target);
    };
  });
}
