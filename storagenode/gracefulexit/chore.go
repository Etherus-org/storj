// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package gracefulexit

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	"gopkg.in/spacemonkeygo/monkit.v2"

	"storj.io/storj/internal/sync2"
	"storj.io/storj/storagenode/satellites"
)

var mon = monkit.Package()

// Chore checks for satellites that the node is exiting and creates a worker per satellite to complete the process.
//
// architecture: Chore
type Chore struct {
	log         *zap.Logger
	satelliteDB satellites.DB

	config Config

	exitingMap sync.Map
	Loop       sync2.Cycle
	limiter    sync2.Limiter
}

// Config for the chore
type Config struct {
	ChoreInterval time.Duration `help:"how often to run the chore to check for satellites for the node to exit." releaseDefault:"15m" devDefault:"10s"`
	NumWorkers    int           `help:"number of workers to handle satellite exits" default:"3"`
}

// NewChore instantiates Chore.
func NewChore(log *zap.Logger, config Config, satelliteDB satellites.DB) *Chore {
	return &Chore{
		log:         log,
		satelliteDB: satelliteDB,
		config:      config,
		Loop:        *sync2.NewCycle(config.ChoreInterval),
		limiter:     *sync2.NewLimiter(config.NumWorkers),
	}
}

// Run starts the chore.
func (chore *Chore) Run(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	err = chore.Loop.Run(ctx, func(ctx context.Context) (err error) {
		defer mon.Task()(&ctx)(&err)

		chore.log.Info("running graceful exit chore.")

		satellites, err := chore.satelliteDB.ListGracefulExits(ctx)
		if err != nil {
			chore.log.Error("error retrieving satellites.", zap.Error(err))
			return nil
		}

		if len(satellites) == 0 {
			chore.log.Debug("no satellites found.")
			return nil
		}

		for _, satellite := range satellites {
			satelliteID := satellite.SatelliteID
			worker := NewWorker(chore.log, chore.satelliteDB, satelliteID)
			if _, ok := chore.exitingMap.LoadOrStore(satelliteID, worker); ok {
				// already running a worker for this satellite
				chore.log.Debug("skipping graceful exit for satellite. worker already exists.", zap.String("satellite ID", satelliteID.String()))
				continue
			}

			chore.limiter.Go(ctx, func() {
				err := worker.Run(ctx, satelliteID, func() {
					chore.log.Debug("finished graceful exit for satellite.", zap.String("satellite ID", satelliteID.String()))
					chore.exitingMap.Delete(satelliteID)
				})
				if err != nil {
					worker.log.Error("worker failed.", zap.Error(err))
				}
			})
		}
		chore.limiter.Wait()

		return nil
	})

	return err
}

// Close closes chore.
func (chore *Chore) Close() error {
	chore.Loop.Close()
	chore.exitingMap.Range(func(key interface{}, value interface{}) bool {
		worker := value.(*Worker)
		err := worker.Close()
		if err != nil {
			worker.log.Error("worker failed on close.", zap.Error(err))
		}
		chore.exitingMap.Delete(key)
		return true
	})

	return nil
}
