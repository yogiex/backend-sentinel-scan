package worker

import "time"

type AutoScaleConfig struct {
	Enabled            bool
	MinWorkers         int
	MaxWorkers         int
	ScaleUpThreshold   int
	ScaleDownThreshold int
	ScaleUpBy          int
	ScaleDownBy        int
	PollInterval       time.Duration
	Cooldown           time.Duration
}

func NewAutoScaler(queueName, workerType string, conn interface{}, pool interface{}, publisher interface{}, cfg AutoScaleConfig) interface{} {
	return nil
}
