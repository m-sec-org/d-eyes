package redis

import (
	"context"
	"encoding/json"
	"time"

	redis "github.com/redis/go-redis/v9"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue"
)

type Queue struct {
	client     *redis.Client
	sortedSet  string
	retryDelay time.Duration
}

func New(client *redis.Client, sortedSet string) *Queue {
	return &Queue{client: client, sortedSet: sortedSet, retryDelay: time.Second}
}

func (q *Queue) Push(ctx context.Context, task *model.Task) error {
	payload, err := json.Marshal(task)
	if err != nil {
		return err
	}
	score := float64(task.Priority)
	return q.client.ZAdd(ctx, q.sortedSet, redis.Z{Score: score, Member: string(payload)}).Err()
}

func (q *Queue) Requeue(ctx context.Context, task *model.Task) error {
	return q.Push(ctx, task)
}

func (q *Queue) Pop(ctx context.Context, caps []string) (*model.Task, error) {
	for {
		res, err := q.client.ZPopMin(ctx, q.sortedSet, 1).Result()
		if err == redis.Nil {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		for _, z := range res {
			var task model.Task
			var raw []byte
			switch v := z.Member.(type) {
			case string:
				raw = []byte(v)
			case []byte:
				raw = v
			default:
				continue
			}
			if err := json.Unmarshal(raw, &task); err != nil {
				continue
			}
			if queue.MatchCapabilities(&task, caps) {
				return &task, nil
			}
			// return to queue since agent lacks capability
			_ = q.Push(ctx, &task)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(q.retryDelay):
		}
	}
}

func (q *Queue) Len(ctx context.Context) (int64, error) {
	return q.client.ZCard(ctx, q.sortedSet).Result()
}

func (q *Queue) Close() error {
	return q.client.Close()
}

var _ queue.Queue = (*Queue)(nil)
