import { useCallback, useState } from 'react';
import { batchTagAssets } from '@/services/api/assetDetail';

export function useBatchTag(onSuccess: () => void) {
  const [loading, setLoading] = useState(false);

  const applyTag = useCallback(
    async (ids: string[], tag: string) => {
      if (ids.length === 0 || !tag.trim()) return;
      setLoading(true);
      try {
        await batchTagAssets(ids, tag);
        onSuccess();
      } finally {
        setLoading(false);
      }
    },
    [onSuccess]
  );

  return { loading, applyTag };
}
