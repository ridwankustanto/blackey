package blackey

import (
	"sync"

	"golang.org/x/time/rate"
)

type RateLimiter struct {
	mu     sync.RWMutex
	limits map[string]*rate.Limiter
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limits: make(map[string]*rate.Limiter),
	}
}

func (rl *RateLimiter) getLimiter(key string, rateLimit int) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limits[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		limiter, exists = rl.limits[key]
		if !exists {
			// Allow bursts up to half the rate limit, minimum of 1
			burst := rateLimit / 2
			if burst < 1 {
				burst = 1
			}
			limiter = rate.NewLimiter(rate.Limit(rateLimit)/60, burst)
			rl.limits[key] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter
}
