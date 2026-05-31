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

type AutoScaler struct{}

func NewAutoScaler(queueName, workerType string, conn interface{}, pool interface{}, publisher interface{}, mqConfig interface{}, cfg AutoScaleConfig) *AutoScaler {
	return &AutoScaler{}
}

func (a *AutoScaler) Start() {}
func (a *AutoScaler) Stop()  {}
