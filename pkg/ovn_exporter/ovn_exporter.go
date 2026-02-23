// Copyright 2018 Paul Greenberg (greenpau@outlook.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ovn_exporter

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/greenpau/ovsdb"
	"github.com/greenpau/versioned"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/version"
)

const (
	namespace    = "ovn"
	ovsSubsystem = "ovs"
)

var (
	app        *versioned.PackageManager
	appVersion string
	gitBranch  string
	gitCommit  string
	buildUser  string
	buildDate  string
)

func init() {
	app = versioned.NewPackageManager("ovn-exporter")
	app.Description = "Prometheus Exporter for Open Virtual Network (OVN)"
	app.Documentation = "https://github.com/supergate-hub/ovn_exporter/"
	app.SetVersion(appVersion, "2.2.0")
	app.SetGitBranch(gitBranch, "")
	app.SetGitCommit(gitCommit, "")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")
}

// =====================================================================
// Common metrics (ovn_* -- always collected, unified across OVN/OVS)
// =====================================================================
var (
	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Is OVN stack up (1) or is it down (0).",
		nil, nil,
	)
	requestErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "failed_requests_total"),
		"The total number of failed requests to OVN stack.",
		nil, nil,
	)
	requestsTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "requests_total"),
		"The total number of requests to OVN stack.",
		nil, nil,
	)
	requestsSuccessful = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "successful_requests_total"),
		"The total number of successful requests to OVN stack.",
		nil, nil,
	)
	nextPoll = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "next_poll_timestamp_seconds"),
		"The timestamp of the next potential poll of OVN stack in seconds.",
		nil, nil,
	)
	pid = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "pid"),
		"The process ID of a running component. If the component is not running, then the ID is 0.",
		[]string{"component", "user", "group"}, nil,
	)
	logFileSize = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "log_file_size_bytes"),
		"The size of a log file associated with a component in bytes.",
		[]string{"component", "filename"}, nil,
	)
	logEventStat = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "log_events_total"),
		"The total number of recorded log messages associated with a component by log severity level and source.",
		[]string{"component", "severity", "source"}, nil,
	)
	dbFileSize = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "db_file_size_bytes"),
		"The size of a database file associated with a component in bytes.",
		[]string{"component", "filename"}, nil,
	)
	covAvg = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "coverage_avg"),
		"The average rate of the number of times particular events occur during a daemon's runtime.",
		[]string{"component", "event", "interval"}, nil,
	)
	covTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "coverage_total"),
		"The total number of times particular events occur during a daemon's runtime.",
		[]string{"component", "event"}, nil,
	)
	memUsage = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "memory_usage_bytes"),
		"The memory usage of a component in bytes.",
		[]string{"component", "facility"}, nil,
	)
	clusterEnabled = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_enabled"),
		"Is clustering enabled (1) or not (0).",
		[]string{"component"}, nil,
	)
	clusterPeerInConnInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_inbound_peer_connected"),
		"This metric appears when a cluster peer is connected to this server. This metric is always 1.",
		[]string{"component", "server_id", "cluster_id", "peer_id", "peer_address"}, nil,
	)
	clusterPeerOutConnInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_outbound_peer_connected"),
		"This metric appears when this server connects to a cluster peer. This metric is always 1.",
		[]string{"component", "server_id", "cluster_id", "peer_id", "peer_address"}, nil,
	)
	clusterPeerInConnTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_inbound_peer_conn_total"),
		"The total number of inbound connections from cluster peers.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterPeerOutConnTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_outbound_peer_conn_total"),
		"The total number of outbound connections to cluster peers.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterPeerCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_peer_count"),
		"The total number of peers in this server's cluster.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterRole = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_role"),
		"The role of this server in the cluster. The values are: 3 - leader, 2 - candidate, 1 - follower, 0 - other.",
		[]string{"component", "server_id", "server_uuid", "cluster_id", "cluster_uuid"}, nil,
	)
	clusterStatus = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_status"),
		"The status of this server in the cluster. The values are: 1 - cluster member, 0 - other.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterTerm = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_term"),
		"The current raft term known by this server.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterNotCommittedEntryCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_uncommitted_entry_count"),
		"The number of raft entries not yet committed by this server.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterNotAppliedEntryCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_pending_entry_count"),
		"The number of raft entries not yet applied by this server.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterPeerNextIndex = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_peer_next_index"),
		"The raft's next index associated with this cluster peer.",
		[]string{"component", "server_id", "cluster_id", "peer_id"}, nil,
	)
	clusterPeerMatchIndex = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_peer_match_index"),
		"The raft's match index associated with this cluster peer.",
		[]string{"component", "server_id", "cluster_id", "peer_id"}, nil,
	)
	clusterLeaderSelf = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_leader_self"),
		"Is this server consider itself a leader (1) or not (0).",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterVoteSelf = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_vote_self"),
		"Is this server voted itself as a leader (1) or not (0).",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterNextIndex = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_next_index"),
		"The raft's next index associated with this server.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterMatchIndex = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_match_index"),
		"The raft's match index associated with this server.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterLogLowIndex = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_log_low_index"),
		"The raft's low number associated with this server.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
	clusterLogHighIndex = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_log_high_index"),
		"The raft's high number associated with this server.",
		[]string{"component", "server_id", "cluster_id"}, nil,
	)
)

// =====================================================================
// OVN domain-specific metrics (ovn_*)
// =====================================================================
var (
	chassisInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "chassis_nb_cfg_timestamp_milliseconds"),
		"The nb_cfg_timestamp from OVN Chassis_Private table in milliseconds. Value is 0 if chassis has no entry in Chassis_Private (not reporting).",
		[]string{"uuid", "name", "ip"}, nil,
	)
	chassisNbCfg = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "chassis_nb_cfg"),
		"The nb_cfg (configuration sequence number) from OVN Chassis_Private table. Value is 0 if chassis has no entry in Chassis_Private (not reporting).",
		[]string{"uuid", "name", "ip"}, nil,
	)
	logicalSwitchInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_switch_info"),
		"The information about OVN logical switch. This metric is always up (1).",
		[]string{"uuid", "name"}, nil,
	)
	logicalSwitchExternalIDs = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_switch_external_id"),
		"Provides the external IDs and values associated with OVN logical switches. This metric is always up (1).",
		[]string{"uuid", "key", "value"}, nil,
	)
	logicalSwitchPortBinding = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_switch_port_binding"),
		"Provides the association between a logical switch and a logical switch port. This metric is always up (1).",
		[]string{"uuid", "port"}, nil,
	)
	logicalSwitchTunnelKey = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_switch_tunnel_key"),
		"The value of the tunnel key associated with the logical switch.",
		[]string{"uuid"}, nil,
	)
	logicalSwitchPorts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_switch_ports"),
		"The number of logical switch ports connected to the OVN logical switch.",
		[]string{"uuid"}, nil,
	)
	logicalSwitchPortInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_switch_port_info"),
		"The information about OVN logical switch port. This metric is always up (1).",
		[]string{
			"uuid",
			"name",
			"chassis",
			"logical_switch",
			"datapath",
			"port_binding",
			"mac_address",
			"ip_address",
		}, nil,
	)
	logicalSwitchPortTunnelKey = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_switch_port_tunnel_key"),
		"The value of the tunnel key associated with the logical switch port.",
		[]string{"uuid"}, nil,
	)
	logicalRouterInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_router_info"),
		"The information about OVN logical router. This metric is always up (1).",
		[]string{"uuid", "name"}, nil,
	)
	logicalRouterExternalIDs = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_router_external_id"),
		"Provides the external IDs and values associated with OVN logical routers. This metric is always up (1).",
		[]string{"uuid", "key", "value"}, nil,
	)
	logicalRouterPorts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_router_ports"),
		"The number of logical router ports connected to the OVN logical router.",
		[]string{"uuid"}, nil,
	)
	logicalRouterStaticRoutes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_router_static_routes"),
		"The number of static routes configured on the OVN logical router.",
		[]string{"uuid"}, nil,
	)
	logicalRouterNatRules = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_router_nat_rules"),
		"The number of NAT rules configured on the OVN logical router.",
		[]string{"uuid"}, nil,
	)
	logicalRouterLoadBalancers = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_router_load_balancers"),
		"The number of load balancers associated with the OVN logical router.",
		[]string{"uuid"}, nil,
	)
	logicalRouterPolicies = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "logical_router_policies"),
		"The number of policies configured on the OVN logical router.",
		[]string{"uuid"}, nil,
	)
	networkPortUp = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "network_port"),
		"The TCP port used for database connection. If the value is 0, then the port is not in use.",
		[]string{"component", "usage"}, nil,
	)
	clusterGroup = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cluster_group"),
		"The cluster group in which this server participates. It is a combination of SB and NB cluster IDs. This metric is always up (1).",
		[]string{"cluster_group"}, nil,
	)
)

// =====================================================================
// OVS domain-specific metrics (ovn_ovs_*)
// =====================================================================
var (
	ovsInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, ovsSubsystem, "info"),
		"This metric provides basic information about OVS stack. It is always set to 1.",
		[]string{
			"system_id",
			"rundir",
			"hostname",
			"system_type",
			"system_version",
			"ovs_version",
			"db_version",
		}, nil,
	)
)

// Exporter collects OVN/OVS data from the given server and exports them using
// the prometheus metrics package.
type Exporter struct {
	sync.RWMutex
	OvnClient            *ovsdb.OvnClient
	OvsClient            *ovsdb.OvsClient
	ovnEnabled           bool
	ovsEnabled           bool
	timeout              int
	pollInterval         int64
	errors               int64
	totalRequests        int64
	successfulRequests   int64
	requestsLocker       sync.RWMutex
	nextCollectionTicker int64
	metrics              []prometheus.Metric
	logger               log.Logger
}

// Options contains options for the exporter.
type Options struct {
	Timeout    int
	Logger     log.Logger
	OvnEnabled bool
	OvsEnabled bool
}

// NewLogger returns an instance of logger.
func NewLogger(logLevel string) (log.Logger, error) {
	logger := log.NewLogfmtLogger(os.Stderr)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	var levelFilter level.Option
	switch logLevel {
	case "debug":
		levelFilter = level.AllowDebug()
	case "info":
		levelFilter = level.AllowInfo()
	case "warn":
		levelFilter = level.AllowWarn()
	case "error":
		levelFilter = level.AllowError()
	default:
		return nil, fmt.Errorf("invalid log level: %s", logLevel)
	}

	logger = level.NewFilter(logger, levelFilter)
	return logger, nil
}

// NewExporter returns an initialized Exporter.
func NewExporter(opts Options) (*Exporter, error) {
	version.Version = appVersion
	version.Revision = gitCommit
	version.Branch = gitBranch
	version.BuildUser = buildUser
	version.BuildDate = buildDate
	e := Exporter{
		timeout:    opts.Timeout,
		logger:     opts.Logger,
		ovnEnabled: opts.OvnEnabled,
		ovsEnabled: opts.OvsEnabled,
	}
	if opts.OvsEnabled {
		ovsClient := ovsdb.NewOvsClient()
		ovsClient.Timeout = opts.Timeout
		e.OvsClient = ovsClient
	}
	if opts.OvnEnabled {
		ovnClient := ovsdb.NewOvnClient()
		ovnClient.Timeout = opts.Timeout
		e.OvnClient = ovnClient
	}
	return &e, nil
}

// ExporterPerformClientCalls creates client connections.
func ExporterPerformClientCalls(e *Exporter) (*Exporter, error) {
	var errs []error
	if e.ovsEnabled && e.OvsClient != nil {
		level.Debug(e.logger).Log(
			"msg", "ExporterPerformClientCalls() calls OvsClient.Connect()",
		)
		if err := e.OvsClient.Connect(); err != nil {
			errs = append(errs, err)
		} else {
			level.Debug(e.logger).Log(
				"msg", "ExporterPerformClientCalls() calls OvsClient.GetSystemInfo()",
			)
			if err := e.OvsClient.GetSystemInfo(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if e.ovnEnabled && e.OvnClient != nil {
		level.Debug(e.logger).Log(
			"msg", "ExporterPerformClientCalls() calls OvnClient.Connect()",
		)
		if err := e.OvnClient.Connect(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return e, fmt.Errorf("%v", errs)
	}
	level.Debug(e.logger).Log(
		"msg", "ExporterPerformClientCalls() initialized successfully",
	)
	return e, nil
}

// Describe describes all the metrics ever exported by the OVN exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// Always registered (common + unified metrics)
	ch <- up
	ch <- requestErrors
	ch <- requestsTotal
	ch <- requestsSuccessful
	ch <- nextPoll
	ch <- pid
	ch <- logFileSize
	ch <- logEventStat
	ch <- dbFileSize
	ch <- covAvg
	ch <- covTotal
	ch <- memUsage
	ch <- clusterEnabled
	ch <- clusterRole
	ch <- clusterStatus
	ch <- clusterTerm
	ch <- clusterNotCommittedEntryCount
	ch <- clusterNotAppliedEntryCount
	ch <- clusterNextIndex
	ch <- clusterMatchIndex
	ch <- clusterLogLowIndex
	ch <- clusterLogHighIndex
	ch <- clusterLeaderSelf
	ch <- clusterVoteSelf
	ch <- clusterPeerCount
	ch <- clusterPeerInConnTotal
	ch <- clusterPeerOutConnTotal
	ch <- clusterPeerNextIndex
	ch <- clusterPeerMatchIndex
	ch <- clusterPeerInConnInfo
	ch <- clusterPeerOutConnInfo

	// OVS domain-specific metrics
	if e.ovsEnabled {
		ch <- ovsInfo
	}

	// OVN domain-specific metrics
	if e.ovnEnabled {
		ch <- chassisInfo
		ch <- chassisNbCfg
		ch <- logicalSwitchInfo
		ch <- logicalSwitchExternalIDs
		ch <- logicalSwitchPorts
		ch <- logicalSwitchPortBinding
		ch <- logicalSwitchTunnelKey
		ch <- logicalSwitchPortInfo
		ch <- logicalSwitchPortTunnelKey
		ch <- logicalRouterInfo
		ch <- logicalRouterExternalIDs
		ch <- logicalRouterPorts
		ch <- logicalRouterStaticRoutes
		ch <- logicalRouterNatRules
		ch <- logicalRouterLoadBalancers
		ch <- logicalRouterPolicies
		ch <- networkPortUp
		ch <- clusterGroup
	}
}

// IncrementErrorCounter increases the counter of failed queries
// to OVN server.
func (e *Exporter) IncrementErrorCounter() {
	e.requestsLocker.Lock()
	defer e.requestsLocker.Unlock()
	atomic.AddInt64(&e.errors, 1)
	atomic.AddInt64(&e.totalRequests, 1)
}

// IncrementRequestCounter increases the counter of total requests
// to OVN server.
func (e *Exporter) IncrementRequestCounter() {
	e.requestsLocker.Lock()
	defer e.requestsLocker.Unlock()
	atomic.AddInt64(&e.totalRequests, 1)
}

// IncrementSuccessCounter increases the counter of successful queries
// to OVN server.
func (e *Exporter) IncrementSuccessCounter() {
	e.requestsLocker.Lock()
	defer e.requestsLocker.Unlock()
	atomic.AddInt64(&e.successfulRequests, 1)
	atomic.AddInt64(&e.totalRequests, 1)
}

// Collect implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.GatherMetrics()
	level.Debug(e.logger).Log(
		"msg", "Collect() calls RLock()",
	)
	e.RLock()
	defer e.RUnlock()
	if len(e.metrics) == 0 {
		level.Debug(e.logger).Log(
			"msg", "Collect() no metrics found",
		)
		ch <- prometheus.MustNewConstMetric(
			up,
			prometheus.GaugeValue,
			0,
		)
		ch <- prometheus.MustNewConstMetric(
			requestErrors,
			prometheus.CounterValue,
			float64(e.errors),
		)
		ch <- prometheus.MustNewConstMetric(
			requestsTotal,
			prometheus.CounterValue,
			float64(e.totalRequests),
		)
		ch <- prometheus.MustNewConstMetric(
			requestsSuccessful,
			prometheus.CounterValue,
			float64(e.successfulRequests),
		)
		ch <- prometheus.MustNewConstMetric(
			nextPoll,
			prometheus.CounterValue,
			float64(e.nextCollectionTicker),
		)
		return
	}
	level.Debug(e.logger).Log(
		"msg", "Collect() sends metrics to a shared channel",
		"metric_count", len(e.metrics),
	)
	for _, m := range e.metrics {
		ch <- m
	}
}

// GatherMetrics collect data from OVN/OVS server and stores them
// as Prometheus metrics.
func (e *Exporter) GatherMetrics() {
	level.Debug(e.logger).Log(
		"msg", "GatherMetrics() called",
	)
	if time.Now().Unix() < e.nextCollectionTicker {
		return
	}
	e.Lock()
	level.Debug(e.logger).Log(
		"msg", "GatherMetrics() locked",
	)
	defer e.Unlock()
	if len(e.metrics) > 0 {
		e.metrics = e.metrics[:0]
		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() cleared metrics",
		)
	}
	upValue := 1
	isClusterEnabled := false

	if e.ovsEnabled {
		e.gatherOvsMetrics(&upValue, &isClusterEnabled)
	}
	if e.ovnEnabled {
		e.gatherOvnMetrics(&upValue, &isClusterEnabled)
	}
	e.gatherCommonMetrics(upValue)

	e.nextCollectionTicker = time.Now().Add(time.Duration(e.pollInterval) * time.Second).Unix()

	level.Debug(e.logger).Log(
		"msg", "GatherMetrics() returns",
	)
}

// gatherOvsMetrics collects OVS-specific metrics using the OvsClient.
func (e *Exporter) gatherOvsMetrics(upValue *int, isClusterEnabled *bool) {
	// Get OVS system info
	err := e.OvsClient.GetSystemInfo()
	if err != nil {
		level.Error(e.logger).Log(
			"msg", "OvsClient.GetSystemInfo() failed",
			"vswitch_name", e.OvsClient.Database.Vswitch.Name,
			"error", err.Error(),
		)
		e.IncrementErrorCounter()
		*upValue = 0
	} else {
		e.IncrementSuccessCounter()
		level.Debug(e.logger).Log(
			"msg", "OvsClient.GetSystemInfo() successful",
			"vswitch_name", e.OvsClient.Database.Vswitch.Name,
		)
		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			ovsInfo,
			prometheus.GaugeValue,
			1,
			e.OvsClient.System.ID,
			e.OvsClient.System.RunDir,
			e.OvsClient.System.Hostname,
			e.OvsClient.System.Type,
			e.OvsClient.System.Version,
			e.OvsClient.Database.Vswitch.Version,
			e.OvsClient.Database.Vswitch.Schema.Version,
		))
	}

	// Process info for OVS components
	ovsComponents := []string{
		"ovsdb-server",
		"ovs-vswitchd",
	}
	for _, component := range ovsComponents {
		p, err := e.OvsClient.GetProcessInfo(component)
		level.Debug(e.logger).Log(
			"msg", "gatherOvsMetrics() calls GetProcessInfo()",
			"component", component,
		)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "GetProcessInfo() failed",
				"component", component,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			*upValue = 0
		} else {
			e.IncrementSuccessCounter()
		}
		if p.ID > 0 {
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				pid,
				prometheus.GaugeValue,
				float64(p.ID),
				component,
				p.User,
				p.Group,
			))
		}
		level.Debug(e.logger).Log(
			"msg", "gatherOvsMetrics() completed GetProcessInfo()",
			"component", component,
		)
	}

	// Log file info for OVS components
	ovsLogComponents := []string{
		"ovsdb-server",
		"ovs-vswitchd",
	}
	for _, component := range ovsLogComponents {
		level.Debug(e.logger).Log(
			"msg", "gatherOvsMetrics() calls GetLogFileInfo()",
			"component", component,
		)
		file, err := e.OvsClient.GetLogFileInfo(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "GetLogFileInfo() failed",
				"component", component,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			continue
		} else {
			e.IncrementSuccessCounter()
		}
		level.Debug(e.logger).Log(
			"msg", "gatherOvsMetrics() completed GetLogFileInfo()",
			"component", component,
		)
		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			logFileSize,
			prometheus.GaugeValue,
			float64(file.Info.Size()),
			file.Component,
			file.Path,
		))
		level.Debug(e.logger).Log(
			"msg", "gatherOvsMetrics() calls GetLogFileEventStats()",
			"component", component,
		)
		eventStats, err := e.OvsClient.GetLogFileEventStats(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "GetLogFileEventStats() failed",
				"component", component,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			continue
		} else {
			e.IncrementSuccessCounter()
		}
		level.Debug(e.logger).Log(
			"msg", "gatherOvsMetrics() completed GetLogFileEventStats()",
			"component", component,
		)
		for sev, sources := range eventStats {
			for source, count := range sources {
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					logEventStat,
					prometheus.GaugeValue,
					float64(count),
					component,
					sev,
					source,
				))
			}
		}
	}

	// AppListCommands for OVS ovsdb-server
	ovsAppComponents := []string{
		"ovsdb-server",
	}
	for _, component := range ovsAppComponents {
		level.Debug(e.logger).Log(
			"msg", "gatherOvsMetrics() calls AppListCommands()",
			"component", component,
		)
		cmds, err := e.OvsClient.AppListCommands(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "AppListCommands() failed",
				"component", component,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			level.Debug(e.logger).Log(
				"msg", "gatherOvsMetrics() completed AppListCommands()",
				"component", component,
			)
			continue
		}
		e.IncrementSuccessCounter()
		level.Debug(e.logger).Log(
			"msg", "gatherOvsMetrics() completed AppListCommands()",
			"component", component,
		)
		if cmds["coverage/show"] {
			level.Debug(e.logger).Log(
				"msg", "gatherOvsMetrics() calls GetAppCoverageMetrics()",
				"component", component,
			)
			if metrics, err := e.OvsClient.GetAppCoverageMetrics(component); err != nil {
				level.Error(e.logger).Log(
					"msg", "GetAppCoverageMetrics() failed",
					"component", component,
					"error", err.Error(),
				)
				e.IncrementErrorCounter()
			} else {
				e.IncrementSuccessCounter()
				for event, metric := range metrics {
					for period, value := range metric {
						if period == "total" {
							e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
								covTotal,
								prometheus.CounterValue,
								value,
								component,
								event,
							))
						} else {
							e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
								covAvg,
								prometheus.GaugeValue,
								value,
								component,
								event,
								period,
							))
						}
					}
				}
			}
			level.Debug(e.logger).Log(
				"msg", "gatherOvsMetrics() completed GetAppCoverageMetrics()",
				"component", component,
			)
		}
		if cmds["memory/show"] {
			level.Debug(e.logger).Log(
				"msg", "gatherOvsMetrics() calls GetAppMemoryMetrics()",
				"component", component,
			)
			if metrics, err := e.OvsClient.GetAppMemoryMetrics(component); err != nil {
				level.Error(e.logger).Log(
					"msg", "GetAppMemoryMetrics() failed",
					"component", component,
					"error", err.Error(),
				)
				e.IncrementErrorCounter()
			} else {
				e.IncrementSuccessCounter()
				for facility, value := range metrics {
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						memUsage,
						prometheus.GaugeValue,
						value,
						component,
						facility,
					))
				}
			}
			level.Debug(e.logger).Log(
				"msg", "gatherOvsMetrics() completed GetAppMemoryMetrics()",
				"component", component,
			)
		}
	}
}

// gatherOvnMetrics collects OVN-specific metrics using the OvnClient.
func (e *Exporter) gatherOvnMetrics(upValue *int, isClusterEnabled *bool) {
	// Chassis info
	level.Debug(e.logger).Log(
		"msg", "gatherOvnMetrics() calls GetChassis()",
	)
	if vteps, err := e.OvnClient.GetChassis(); err != nil {
		level.Error(e.logger).Log(
			"msg", "GetChassis() failed",
			"southbound_db_name", e.OvnClient.Database.Southbound.Name,
			"error", err.Error(),
		)
		e.IncrementErrorCounter()
		*upValue = 0
	} else {
		e.IncrementSuccessCounter()
		for _, vtep := range vteps {
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				chassisInfo,
				prometheus.GaugeValue,
				float64(vtep.NbCfgTimestamp),
				vtep.UUID,
				vtep.Name,
				vtep.IPAddress.String(),
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				chassisNbCfg,
				prometheus.GaugeValue,
				float64(vtep.NbCfg),
				vtep.UUID,
				vtep.Name,
				vtep.IPAddress.String(),
			))
		}
	}
	level.Debug(e.logger).Log(
		"msg", "gatherOvnMetrics() completed GetChassis()",
	)

	// Logical Switches
	level.Debug(e.logger).Log(
		"msg", "gatherOvnMetrics() calls GetLogicalSwitches()",
	)
	lsws, err := e.OvnClient.GetLogicalSwitches()
	if err != nil {
		level.Error(e.logger).Log(
			"msg", "GetLogicalSwitches() failed",
			"southbound_db_name", e.OvnClient.Database.Southbound.Name,
			"error", err.Error(),
		)
		e.IncrementErrorCounter()
		*upValue = 0
	} else {
		e.IncrementSuccessCounter()
		for _, lsw := range lsws {
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalSwitchInfo,
				prometheus.GaugeValue,
				1,
				lsw.UUID,
				lsw.Name,
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalSwitchPorts,
				prometheus.GaugeValue,
				float64(len(lsw.Ports)),
				lsw.UUID,
			))
			if len(lsw.Ports) > 0 {
				for _, p := range lsw.Ports {
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						logicalSwitchPortBinding,
						prometheus.GaugeValue,
						1,
						lsw.UUID,
						p,
					))
				}
			}
			if len(lsw.ExternalIDs) > 0 {
				for k, v := range lsw.ExternalIDs {
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						logicalSwitchExternalIDs,
						prometheus.GaugeValue,
						1,
						lsw.UUID,
						k,
						v,
					))
				}
			}
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalSwitchTunnelKey,
				prometheus.GaugeValue,
				float64(lsw.TunnelKey),
				lsw.UUID,
			))
		}
	}
	level.Debug(e.logger).Log(
		"msg", "gatherOvnMetrics() completed GetLogicalSwitches()",
	)

	// Logical Switch Ports
	level.Debug(e.logger).Log(
		"msg", "gatherOvnMetrics() calls GetLogicalSwitchPorts()",
	)
	lswps, err := e.OvnClient.GetLogicalSwitchPorts()
	if err != nil {
		level.Error(e.logger).Log(
			"msg", "GetLogicalSwitchPorts() failed",
			"southbound_db_name", e.OvnClient.Database.Southbound.Name,
			"error", err.Error(),
		)
		e.IncrementErrorCounter()
		*upValue = 0
	} else {
		e.IncrementSuccessCounter()
		for _, port := range lswps {
			macAddr := "<nil>"
			ipAddr := "<nil>"

			// Find first MAC address
			for _, a := range port.Addresses {
				if a.MacAddress != nil {
					macAddr = a.MacAddress.String()
					break
				}
			}

			// Find first IP address
			for _, a := range port.Addresses {
				if len(a.IPAddresses) > 0 {
					ipAddr = a.IPAddresses[0].String()
					break
				}
			}

			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalSwitchPortInfo,
				prometheus.GaugeValue,
				float64(1),
				port.UUID,
				port.Name,
				port.ChassisUUID,
				port.LogicalSwitchName,
				port.DatapathUUID,
				port.PortBindingUUID,
				macAddr,
				ipAddr,
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalSwitchPortTunnelKey,
				prometheus.GaugeValue,
				float64(port.TunnelKey),
				port.UUID,
			))
		}
	}
	level.Debug(e.logger).Log(
		"msg", "gatherOvnMetrics() completed GetLogicalSwitchPorts()",
	)

	// Logical Routers
	level.Debug(e.logger).Log(
		"msg", "gatherOvnMetrics() calls GetLogicalRouters()",
	)
	routers, err := e.GetLogicalRouters()
	if err != nil {
		level.Error(e.logger).Log(
			"msg", "GetLogicalRouters() failed",
			"northbound_db_name", e.OvnClient.Database.Northbound.Name,
			"error", err.Error(),
		)
		e.IncrementErrorCounter()
		*upValue = 0
	} else {
		e.IncrementSuccessCounter()
		for _, router := range routers {
			// Basic router info metric
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalRouterInfo,
				prometheus.GaugeValue,
				1,
				router.UUID,
				router.Name,
			))

			// Router ports count
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalRouterPorts,
				prometheus.GaugeValue,
				float64(len(router.Ports)),
				router.UUID,
			))

			// Static routes count
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalRouterStaticRoutes,
				prometheus.GaugeValue,
				float64(len(router.StaticRoutes)),
				router.UUID,
			))

			// NAT rules count
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalRouterNatRules,
				prometheus.GaugeValue,
				float64(len(router.NAT)),
				router.UUID,
			))

			// Load balancers count
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalRouterLoadBalancers,
				prometheus.GaugeValue,
				float64(len(router.LoadBalancer)),
				router.UUID,
			))

			// Policies count
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				logicalRouterPolicies,
				prometheus.GaugeValue,
				float64(len(router.Policies)),
				router.UUID,
			))

			// External IDs
			if len(router.ExternalIDs) > 0 {
				for k, v := range router.ExternalIDs {
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						logicalRouterExternalIDs,
						prometheus.GaugeValue,
						1,
						router.UUID,
						k,
						v,
					))
				}
			}
		}
	}
	level.Debug(e.logger).Log(
		"msg", "gatherOvnMetrics() completed GetLogicalRouters()",
	)

	// Process info for OVN components
	ovnProcessComponents := []string{
		"ovsdb-server-southbound",
		"ovsdb-server-southbound-monitoring",
		"ovsdb-server-northbound",
		"ovsdb-server-northbound-monitoring",
		"ovn-northd",
		"ovn-northd-monitoring",
	}
	for _, component := range ovnProcessComponents {
		p, err := e.OvnClient.GetProcessInfo(component)
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() calls GetProcessInfo()",
			"component", component,
		)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "GetProcessInfo() failed",
				"component", component,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			*upValue = 0
		} else {
			e.IncrementSuccessCounter()
		}
		if p.ID > 0 {
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				pid,
				prometheus.GaugeValue,
				float64(p.ID),
				component,
				p.User,
				p.Group,
			))
		}
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() completed GetProcessInfo()",
			"component", component,
		)
	}

	// Log file info for OVN components
	ovnLogComponents := []string{
		"ovsdb-server-southbound",
		"ovsdb-server-northbound",
		"ovn-northd",
	}
	for _, component := range ovnLogComponents {
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() calls GetLogFileInfo()",
			"component", component,
		)
		file, err := e.OvnClient.GetLogFileInfo(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "GetLogFileInfo() failed",
				"component", component,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			continue
		} else {
			e.IncrementSuccessCounter()
		}
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() completed GetLogFileInfo()",
			"component", component,
		)
		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			logFileSize,
			prometheus.GaugeValue,
			float64(file.Info.Size()),
			file.Component,
			file.Path,
		))
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() calls GetLogFileEventStats()",
			"component", component,
		)
		eventStats, err := e.OvnClient.GetLogFileEventStats(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "GetLogFileEventStats() failed",
				"component", component,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			continue
		} else {
			e.IncrementSuccessCounter()
		}
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() completed GetLogFileEventStats()",
			"component", component,
		)
		for sev, sources := range eventStats {
			for source, count := range sources {
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					logEventStat,
					prometheus.GaugeValue,
					float64(count),
					component,
					sev,
					source,
				))
			}
		}
	}

	// AppListCommands for OVN components (coverage, memory, cluster)
	northClusterID := ""
	southClusterID := ""

	ovnAppComponents := []string{
		"ovsdb-server-southbound",
		"ovsdb-server-northbound",
	}

	for _, component := range ovnAppComponents {
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() calls AppListCommands()",
			"component", component,
		)
		cmds, err := e.OvnClient.AppListCommands(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "AppListCommands() failed",
				"component", component,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			level.Debug(e.logger).Log(
				"msg", "gatherOvnMetrics() completed AppListCommands()",
				"component", component,
			)
			continue
		}
		e.IncrementSuccessCounter()
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() completed AppListCommands()",
			"component", component,
		)
		if cmds["coverage/show"] {
			level.Debug(e.logger).Log(
				"msg", "gatherOvnMetrics() calls GetAppCoverageMetrics()",
				"component", component,
			)
			if metrics, err := e.OvnClient.GetAppCoverageMetrics(component); err != nil {
				level.Error(e.logger).Log(
					"msg", "GetAppCoverageMetrics() failed",
					"component", component,
					"error", err.Error(),
				)
				e.IncrementErrorCounter()
			} else {
				e.IncrementSuccessCounter()
				for event, metric := range metrics {
					for period, value := range metric {
						if period == "total" {
							e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
								covTotal,
								prometheus.CounterValue,
								value,
								component,
								event,
							))
						} else {
							e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
								covAvg,
								prometheus.GaugeValue,
								value,
								component,
								event,
								period,
							))
						}
					}
				}
			}
			level.Debug(e.logger).Log(
				"msg", "gatherOvnMetrics() completed GetAppCoverageMetrics()",
				"component", component,
			)
		}
		if cmds["memory/show"] {
			level.Debug(e.logger).Log(
				"msg", "gatherOvnMetrics() calls GetAppMemoryMetrics()",
				"component", component,
			)
			if metrics, err := e.OvnClient.GetAppMemoryMetrics(component); err != nil {
				level.Error(e.logger).Log(
					"msg", "GetAppMemoryMetrics() failed",
					"component", component,
					"error", err.Error(),
				)
				e.IncrementErrorCounter()
			} else {
				e.IncrementSuccessCounter()
				for facility, value := range metrics {
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						memUsage,
						prometheus.GaugeValue,
						value,
						component,
						facility,
					))
				}
			}
			level.Debug(e.logger).Log(
				"msg", "gatherOvnMetrics() completed GetAppMemoryMetrics()",
				"component", component,
			)
		}
		if cmds["cluster/status DB"] {
			level.Debug(e.logger).Log(
				"msg", "gatherOvnMetrics() calls GetAppClusteringInfo()",
				"component", component,
			)
			if cluster, err := e.OvnClient.GetAppClusteringInfo(component); err != nil {
				*isClusterEnabled = false
				level.Error(e.logger).Log(
					"msg", "GetAppClusteringInfo() failed",
					"component", component,
					"error", err.Error(),
				)
				e.IncrementRequestCounter()
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterEnabled,
					prometheus.GaugeValue,
					0,
					component,
				))
			} else {
				e.IncrementRequestCounter()
				*isClusterEnabled = true
				switch component {
				case "ovsdb-server-southbound":
					southClusterID = cluster.ClusterID
				case "ovsdb-server-northbound":
					northClusterID = cluster.ClusterID
				}
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterEnabled,
					prometheus.GaugeValue,
					1,
					component,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterRole,
					prometheus.GaugeValue,
					float64(cluster.Role),
					component,
					cluster.ID,
					cluster.UUID,
					cluster.ClusterID,
					cluster.ClusterUUID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterStatus,
					prometheus.GaugeValue,
					float64(cluster.Status),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterTerm,
					prometheus.CounterValue,
					float64(cluster.Term),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterNotCommittedEntryCount,
					prometheus.GaugeValue,
					float64(cluster.NotCommittedEntries),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterNotAppliedEntryCount,
					prometheus.GaugeValue,
					float64(cluster.NotAppliedEntries),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterNextIndex,
					prometheus.CounterValue,
					float64(cluster.NextIndex),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterMatchIndex,
					prometheus.CounterValue,
					float64(cluster.MatchIndex),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterLogLowIndex,
					prometheus.CounterValue,
					float64(cluster.Log.Low),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterLogHighIndex,
					prometheus.CounterValue,
					float64(cluster.Log.High),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterLeaderSelf,
					prometheus.GaugeValue,
					float64(cluster.IsLeaderSelf),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterVoteSelf,
					prometheus.GaugeValue,
					float64(cluster.IsVotedSelf),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterPeerCount,
					prometheus.GaugeValue,
					float64(len(cluster.Peers)),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterPeerInConnTotal,
					prometheus.GaugeValue,
					float64(cluster.Connections.Inbound),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					clusterPeerOutConnTotal,
					prometheus.GaugeValue,
					float64(cluster.Connections.Outbound),
					component,
					cluster.ID,
					cluster.ClusterID,
				))
				for peerID, peer := range cluster.Peers {
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						clusterPeerNextIndex,
						prometheus.CounterValue,
						float64(peer.NextIndex),
						component,
						cluster.ID,
						cluster.ClusterID,
						peerID,
					))
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						clusterPeerMatchIndex,
						prometheus.CounterValue,
						float64(peer.MatchIndex),
						component,
						cluster.ID,
						cluster.ClusterID,
						peerID,
					))
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						clusterPeerInConnInfo,
						prometheus.GaugeValue,
						float64(peer.Connection.Inbound),
						component,
						cluster.ID,
						cluster.ClusterID,
						peerID,
						peer.Address,
					))
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						clusterPeerOutConnInfo,
						prometheus.GaugeValue,
						float64(peer.Connection.Outbound),
						component,
						cluster.ID,
						cluster.ClusterID,
						peerID,
						peer.Address,
					))
				}
			}
			level.Debug(e.logger).Log(
				"msg", "gatherOvnMetrics() completed GetAppClusteringInfo()",
				"component", component,
			)
		}
	}

	// Cluster group metric
	if northClusterID != "" && southClusterID != "" {
		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			clusterGroup,
			prometheus.GaugeValue,
			1,
			northClusterID+southClusterID,
		))
	}

	// Network port checks
	ovnPortComponents := []string{
		"ovsdb-server-southbound",
		"ovsdb-server-northbound",
	}

	for _, component := range ovnPortComponents {
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() calls IsDefaultPortUp()",
			"component", component,
		)
		defaultPortUp, err := e.OvnClient.IsDefaultPortUp(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "IsDefaultPortUp() failed",
				"component", component,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
		} else {
			e.IncrementSuccessCounter()
		}
		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			networkPortUp,
			prometheus.GaugeValue,
			float64(defaultPortUp),
			component,
			"default",
		))
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() completed IsDefaultPortUp()",
			"component", component,
		)

		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() calls IsSslPortUp()",
			"component", component,
		)
		sslPortUp, err := e.OvnClient.IsSslPortUp(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "IsSslPortUp() failed",
				"component", component,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
		} else {
			e.IncrementSuccessCounter()
		}
		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			networkPortUp,
			prometheus.GaugeValue,
			float64(sslPortUp),
			component,
			"ssl",
		))
		level.Debug(e.logger).Log(
			"msg", "gatherOvnMetrics() completed IsSslPortUp()",
			"component", component,
		)

		if *isClusterEnabled {
			level.Debug(e.logger).Log(
				"msg", "gatherOvnMetrics() calls IsRaftPortUp()",
				"component", component,
			)
			raftPortUp, err := e.OvnClient.IsRaftPortUp(component)
			if err != nil {
				level.Error(e.logger).Log(
					"msg", "IsRaftPortUp() failed",
					"component", component,
					"error", err.Error(),
				)
				e.IncrementErrorCounter()
			} else {
				e.IncrementSuccessCounter()
			}
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				networkPortUp,
				prometheus.GaugeValue,
				float64(raftPortUp),
				component,
				"raft",
			))
			level.Debug(e.logger).Log(
				"msg", "gatherOvnMetrics() completed IsRaftPortUp()",
				"component", component,
			)
		}
	}
}

// gatherCommonMetrics collects metrics common to both OVN and OVS.
func (e *Exporter) gatherCommonMetrics(upValue int) {
	e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
		up,
		prometheus.GaugeValue,
		float64(upValue),
	))

	e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
		requestErrors,
		prometheus.CounterValue,
		float64(e.errors),
	))

	e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
		requestsTotal,
		prometheus.CounterValue,
		float64(e.totalRequests),
	))

	e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
		requestsSuccessful,
		prometheus.CounterValue,
		float64(e.successfulRequests),
	))

	e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
		nextPoll,
		prometheus.CounterValue,
		float64(e.nextCollectionTicker),
	))
}

// OvnLogicalRouter holds basic information about a logical router
type OvnLogicalRouter struct {
	UUID         string            `json:"uuid" yaml:"uuid"`
	Name         string            `json:"name" yaml:"name"`
	ExternalIDs  map[string]string `json:"external_ids" yaml:"external_ids"`
	Ports        []string          `json:"ports" yaml:"ports"`
	StaticRoutes []string          `json:"static_routes" yaml:"static_routes"`
	NAT          []string          `json:"nat" yaml:"nat"`
	LoadBalancer []string          `json:"load_balancer" yaml:"load_balancer"`
	Policies     []string          `json:"policies" yaml:"policies"`
}

// GetLogicalRouters returns a list of OVN logical routers from the Northbound database
func (e *Exporter) GetLogicalRouters() ([]*OvnLogicalRouter, error) {
	routers := []*OvnLogicalRouter{}

	// Query the Logical_Router table in the Northbound database
	query := "SELECT _uuid, external_ids, name, ports, static_routes, nat, load_balancer, policies FROM Logical_Router"
	result, err := e.OvnClient.Database.Northbound.Client.Transact(e.OvnClient.Database.Northbound.Name, query)
	if err != nil {
		return nil, fmt.Errorf("%s: 'Logical_Router' table error: %s", e.OvnClient.Database.Northbound.Name, err)
	}

	if len(result.Rows) == 0 {
		// No routers found is not an error, just return empty list
		return routers, nil
	}

	for _, row := range result.Rows {
		router := &OvnLogicalRouter{}

		// Get UUID
		if r, dt, err := row.GetColumnValue("_uuid", result.Columns); err == nil && dt == "string" {
			router.UUID = r.(string)
		} else {
			continue
		}

		// Get Name
		if r, dt, err := row.GetColumnValue("name", result.Columns); err == nil && dt == "string" {
			router.Name = r.(string)
		}

		// Get External IDs
		if r, dt, err := row.GetColumnValue("external_ids", result.Columns); err == nil && dt == "map[string]string" {
			router.ExternalIDs = r.(map[string]string)
		} else {
			router.ExternalIDs = make(map[string]string)
		}

		// Get Ports
		if r, dt, err := row.GetColumnValue("ports", result.Columns); err == nil {
			switch dt {
			case "string":
				router.Ports = append(router.Ports, r.(string))
			case "[]string":
				router.Ports = r.([]string)
			}
		}

		// Get Static Routes
		if r, dt, err := row.GetColumnValue("static_routes", result.Columns); err == nil {
			switch dt {
			case "string":
				router.StaticRoutes = append(router.StaticRoutes, r.(string))
			case "[]string":
				router.StaticRoutes = r.([]string)
			}
		}

		// Get NAT rules
		if r, dt, err := row.GetColumnValue("nat", result.Columns); err == nil {
			switch dt {
			case "string":
				router.NAT = append(router.NAT, r.(string))
			case "[]string":
				router.NAT = r.([]string)
			}
		}

		// Get Load Balancers
		if r, dt, err := row.GetColumnValue("load_balancer", result.Columns); err == nil {
			switch dt {
			case "string":
				router.LoadBalancer = append(router.LoadBalancer, r.(string))
			case "[]string":
				router.LoadBalancer = r.([]string)
			}
		}

		// Get Policies
		if r, dt, err := row.GetColumnValue("policies", result.Columns); err == nil {
			switch dt {
			case "string":
				router.Policies = append(router.Policies, r.(string))
			case "[]string":
				router.Policies = r.([]string)
			}
		}

		routers = append(routers, router)
	}

	return routers, nil
}

func init() {
	// Note: version.NewCollector has been removed in newer prometheus/common versions
	// The build info is now exposed via the standard prometheus collector
}

// GetVersionInfo returns exporter info.
func GetVersionInfo() string {
	return version.Info()
}

// GetVersionBuildContext returns exporter build context.
func GetVersionBuildContext() string {
	return version.BuildContext()
}

// GetVersion returns exporter version.
func GetVersion() string {
	return version.Version
}

// GetRevision returns exporter revision.
func GetRevision() string {
	return version.Revision
}

// GetExporterName returns exporter name.
func GetExporterName() string {
	return app.Name
}

// GetExporterVersion return full version info.
func GetExporterVersion() string {
	return app.Banner()
}

// SetPollInterval sets exporter's polling interval.
func (e *Exporter) SetPollInterval(i int64) {
	e.pollInterval = i
}
