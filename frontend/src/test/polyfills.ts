import { TransformStream, WritableStream, ReadableStream } from 'stream/web';

if (typeof globalThis.TransformStream === 'undefined') {
  (globalThis as any).TransformStream = TransformStream;
}
if (typeof globalThis.WritableStream === 'undefined') {
  (globalThis as any).WritableStream = WritableStream;
}
if (typeof globalThis.ReadableStream === 'undefined') {
  (globalThis as any).ReadableStream = ReadableStream;
}

const noop = () => {};

if (typeof window !== 'undefined') {
  if (typeof window.matchMedia !== 'function') {
    window.matchMedia = (() => ({
      matches: false,
      media: '',
      onchange: null,
      addListener: noop,
      removeListener: noop,
      addEventListener: noop,
      removeEventListener: noop,
      dispatchEvent: () => false,
    })) as typeof window.matchMedia;
  }
  window.getComputedStyle = (() =>
    ({
      getPropertyValue: () => '',
      overflow: 'hidden',
      overflowX: 'hidden',
      overflowY: 'hidden',
      width: '0px',
      height: '0px',
    } as CSSStyleDeclaration)) as typeof window.getComputedStyle;
}

if (typeof URL.createObjectURL !== 'function') {
  (URL as any).createObjectURL = () => 'blob:mock';
}
if (typeof URL.revokeObjectURL !== 'function') {
  (URL as any).revokeObjectURL = () => {};
}
