// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package nodemgmt

import (
	"context"
	"sort"

	"go.uber.org/zap"
	"gopkg.in/spacemonkeygo/monkit.v2"

	"storj.io/storj/pkg/identity"
	"storj.io/storj/pkg/pb"
	"storj.io/storj/pkg/rpc/rpcstatus"
	"storj.io/storj/satellite/accounting"
	"storj.io/storj/satellite/overlay"
)

var (
	mon = monkit.Package()
)

// Endpoint for querying node stats for the SNO
//
// architecture: Endpoint
type Endpoint struct {
	log        *zap.Logger
	overlay    overlay.DB
	accounting accounting.StoragenodeAccounting
	cfg        *Config
}

// Config defines values needed by Node Management Endpoint
type Config struct {
	Managers        []string `help:"List of satellite manager ids" default:""`
	DefaultPageSize int      `help:"Default request page limit" default:"10"`
}

// NewEndpoint creates new endpoint
func NewEndpoint(cfg *Config, log *zap.Logger, overlay overlay.DB, accounting accounting.StoragenodeAccounting) *Endpoint {
	edp := &Endpoint{
		log:        log,
		overlay:    overlay,
		accounting: accounting,
		cfg:        cfg,
	}
	sort.Strings(edp.cfg.Managers)
	return edp
}

func (c *Config) isManager(id string) bool {
	if len(c.Managers) == 0 {
		return false
	}
	i := sort.SearchStrings(c.Managers, id)
	return c.Managers[i] == id
}

func (c *Config) getPageNormalized(page *pb.Pagination) *pb.Pagination {
	if page != nil {
		return page
	}
	return &pb.Pagination{
		Limit: uint32(c.DefaultPageSize),
	}
}

// GetMgmtStats sends nodes stats for requested nodes
func (e *Endpoint) GetMgmtStats(ctx context.Context, req *pb.GetMgmtStatsRequest) (_ *pb.GetMgmtStatsResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	peer, err := identity.PeerIdentityFromContext(ctx)
	if err != nil {
		return nil, rpcstatus.Error(rpcstatus.Unauthenticated, err.Error())
	}
	peerID := peer.ID.String()
	if !e.cfg.isManager(peerID) {
		return nil, rpcstatus.Error(rpcstatus.PermissionDenied, peerID+" is not a manager")
	}

	e.log.Debug("GetMgmtStats", zap.String("peer", peerID))

	page := e.cfg.getPageNormalized(req.Page)
	nodes, hasMore, err := e.overlay.Paginate(ctx, int64(page.Offset), int(page.Limit))

	if err != nil {
		if overlay.ErrNodeNotFound.Has(err) {
			return nil, rpcstatus.Error(rpcstatus.PermissionDenied, err.Error())
		}
		e.log.Error("overlay.Get failed", zap.Error(err))
		return nil, rpcstatus.Error(rpcstatus.Internal, err.Error())
	}

	nodeStats := make([]*pb.GetMgmtStatsResponse_NodeStats, len(nodes))
	for i, node := range nodes {
		uptimeScore := calculateReputationScore(
			node.Reputation.UptimeReputationAlpha,
			node.Reputation.UptimeReputationBeta)

		auditScore := calculateReputationScore(
			node.Reputation.AuditReputationAlpha,
			node.Reputation.AuditReputationBeta)

		nodeStats[i] = &pb.GetMgmtStatsResponse_NodeStats{
			NodeId: node.Id,
			Stats: &pb.GetMgmtStatsResponse_Stats{
				UptimeCheck: &pb.GetMgmtStatsResponse_Reputation{
					TotalCount:      node.Reputation.UptimeCount,
					SuccessCount:    node.Reputation.UptimeSuccessCount,
					ReputationAlpha: node.Reputation.UptimeReputationAlpha,
					ReputationBeta:  node.Reputation.UptimeReputationBeta,
					ReputationScore: uptimeScore,
				},
				AuditCheck: &pb.GetMgmtStatsResponse_Reputation{
					TotalCount:      node.Reputation.AuditCount,
					SuccessCount:    node.Reputation.AuditSuccessCount,
					ReputationAlpha: node.Reputation.AuditReputationAlpha,
					ReputationBeta:  node.Reputation.AuditReputationBeta,
					ReputationScore: auditScore,
				},
				Disqualified: node.Disqualified,
			},
		}
	}

	return &pb.GetMgmtStatsResponse{
		NextPage: func() *pb.Pagination {
			if hasMore {
				return &pb.Pagination{
					Limit:  page.Limit,
					Offset: page.Offset + 1,
				}
			}
			return nil
		}(),
		NodeStats: nodeStats,
	}, nil
}

// GetMgmtStorageUsage returns slice of daily storage usage for given period of time sorted in ASC order by date for requested nodes
func (e *Endpoint) GetMgmtStorageUsage(ctx context.Context, req *pb.GetMgmtStorageUsageRequest) (_ *pb.GetMgmtStorageUsageResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	peer, err := identity.PeerIdentityFromContext(ctx)
	if err != nil {
		return nil, rpcstatus.Error(rpcstatus.Unauthenticated, err.Error())
	}
	peerID := peer.ID.String()
	if !e.cfg.isManager(peerID) {
		return nil, rpcstatus.Error(rpcstatus.PermissionDenied, peerID+" is not a manager")
	}

	e.log.Debug("GetMgmtStorageUsage", zap.String("peer", peerID), zap.Time("from", req.GetFrom()), zap.Time("to", req.GetTo()))

	page := e.cfg.getPageNormalized(req.Page)
	nodes, hasMore, err := e.overlay.Paginate(ctx, int64(page.Offset), int(page.Limit))

	if err != nil {
		if overlay.ErrNodeNotFound.Has(err) {
			return nil, rpcstatus.Error(rpcstatus.PermissionDenied, err.Error())
		}
		e.log.Error("overlay.Get failed", zap.Error(err))
		return nil, rpcstatus.Error(rpcstatus.Internal, err.Error())
	}

	nodeStorageUsage := make([]*pb.GetMgmtStorageUsageResponse_NodeStorageUsage, len(nodes))
	for i, node := range nodes {
		nodeSpaceUsages, err := e.accounting.QueryStorageNodeUsage(ctx, node.Id, req.GetFrom(), req.GetTo())
		if err != nil {
			e.log.Error("accounting.QueryStorageNodeUsage failed", zap.Error(err))
			return nil, rpcstatus.Error(rpcstatus.Internal, err.Error())
		}
		nodeStorageUsage[i] = &pb.GetMgmtStorageUsageResponse_NodeStorageUsage{
			NodeId:       node.Id,
			StorageUsage: toProtoGetMgmtStorageUsage(nodeSpaceUsages),
		}
	}

	return &pb.GetMgmtStorageUsageResponse{
		NextPage: func() *pb.Pagination {
			if hasMore {
				return &pb.Pagination{
					Limit:  page.Limit,
					Offset: page.Offset + 1,
				}
			}
			return nil
		}(),
		NodeStorageUsage: nodeStorageUsage,
	}, nil
}

// toProtoGetMgmtStorageUsage converts StorageNodeUsage to PB GetMgmtStorageUsageResponse_StorageUsage
func toProtoGetMgmtStorageUsage(usages []accounting.StorageNodeUsage) []*pb.GetMgmtStorageUsageResponse_StorageUsage {
	var pbUsages []*pb.GetMgmtStorageUsageResponse_StorageUsage

	for _, usage := range usages {
		pbUsages = append(pbUsages, &pb.GetMgmtStorageUsageResponse_StorageUsage{
			AtRestTotal: usage.StorageUsed,
			Timestamp:   usage.Timestamp,
		})
	}

	return pbUsages
}

// calculateReputationScore is helper method to calculate reputation score value
func calculateReputationScore(alpha, beta float64) float64 {
	return alpha / (alpha + beta)
}
