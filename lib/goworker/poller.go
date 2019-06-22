package goworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"gopkg.in/redis.v5"
)

type poller struct {
	process
	isStrict bool
}

func newPoller(queues []string, isStrict bool) (*poller, error) {
	process, err := newProcess("poller", queues)
	if err != nil {
		return nil, err
	}
	return &poller{
		process:  *process,
		isStrict: isStrict,
	}, nil
}

func (p *poller) getJob() (*Job, error) {
	for _, queue := range p.queues(p.isStrict) {
		logger.Debugf("Checking %s", queue)

		reply, err := redisClient.LPop(fmt.Sprintf("%squeue:%s", workerSettings.Namespace, queue)).Bytes()
		if err != nil && err != redis.Nil {
			return nil, err
		}

		if reply != nil {
			logger.Debugf("Found job on %s", queue)

			job := &Job{Queue: queue}

			decoder := json.NewDecoder(bytes.NewReader(reply))
			if workerSettings.UseNumber {
				decoder.UseNumber()
			}

			if err := decoder.Decode(&job.Payload); err != nil {
				return nil, err
			}
			return job, nil
		}
	}

	return nil, nil
}

func (p *poller) poll(pollerNum int, interval time.Duration, ctx context.Context) <-chan *Job {
	jobs := make(chan *Job)
	pollerCount := int64(pollerNum)

	for i := 0; i < pollerNum; i++ {
		go func() {
			defer func() {
				// close channel when last poller exit
				if atomic.AddInt64(&pollerCount, -1) == 0 {
					close(jobs)
				}
			}()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					job, err := p.getJob()
					if err != nil {
						logger.Errorf("Error on %v getting job from %v: %v", p, p.Queues, err)
						continue
					}
					if job != nil {
						select {
						case jobs <- job:
						case <-ctx.Done():
							buf, err := json.Marshal(job.Payload)
							if err != nil {
								logger.Errorf("Error requeueing %v: %v", job, err)
								return
							}

							err = redisClient.LPush(fmt.Sprintf("%squeue:%s", workerSettings.Namespace, job.Queue), buf).Err()
							if err != nil {
								logger.Errorf("Error requeueing %v: %v", job, err)
							}
							return
						}
					} else {
						if workerSettings.ExitOnComplete {
							return
						}
						logger.Debugf("Sleeping for %v", interval)
						logger.Debugf("Waiting for %v", p.Queues)

						timeout := time.After(interval)
						select {
						case <-ctx.Done():
							return
						case <-timeout:
						}
					}
				}
			}
		}()
	}
	return jobs
}
