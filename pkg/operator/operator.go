package operator

import (
	"context"
	"fmt"

	"github.com/khulnasoft/starboard/pkg/compliance"
	"github.com/khulnasoft/starboard/pkg/configauditreport"
	"github.com/khulnasoft/starboard/pkg/ext"
	"github.com/khulnasoft/starboard/pkg/kube"
	"github.com/khulnasoft/starboard/pkg/kubebench"
	"github.com/khulnasoft/starboard/pkg/operator/controller"
	"github.com/khulnasoft/starboard/pkg/operator/etc"
	"github.com/khulnasoft/starboard/pkg/plugin"
	"github.com/khulnasoft/starboard/pkg/starboard"
	"github.com/khulnasoft/starboard/pkg/utils"
	"github.com/khulnasoft/starboard/pkg/vulnerabilityreport"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	setupLog = log.Log.WithName("operator")
)

// Start starts all registered reconcilers and blocks until the context is cancelled.
// Returns an error if there is an error starting any reconciler.
func Start(ctx context.Context, buildInfo starboard.BuildInfo, operatorConfig etc.Config) error {
	installMode, operatorNamespace, targetNamespaces, err := operatorConfig.ResolveInstallMode()
	if err != nil {
		return fmt.Errorf("resolving install mode: %w", err)
	}
	setupLog.Info("Resolved install mode", "install mode", installMode,
		"operator namespace", operatorNamespace,
		"target namespaces", targetNamespaces,
		"exclude namespaces", operatorConfig.ExcludeNamespaces)

	// Set the default manager options.
	skipNameValidation := true // https://github.com/kubernetes-sigs/controller-runtime/issues/2937
	options := manager.Options{
		Scheme:                 starboard.NewScheme(),
		Metrics:                metricsserver.Options{BindAddress: operatorConfig.MetricsBindAddress},
		HealthProbeBindAddress: operatorConfig.HealthProbeBindAddress,
		Cache:                  cache.Options{DefaultTransform: utils.TransformObjMetadata},
		Controller:             controllerconfig.Controller{SkipNameValidation: &skipNameValidation},
	}

	if operatorConfig.LeaderElectionEnabled {
		options.LeaderElection = operatorConfig.LeaderElectionEnabled
		options.LeaderElectionID = operatorConfig.LeaderElectionID
		options.LeaderElectionNamespace = operatorNamespace
	}

	switch installMode {
	case etc.OwnNamespace:
		// Add support for OwnNamespace set in OPERATOR_NAMESPACE (e.g. `starboard-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `starboard-operator`).
		setupLog.Info("Constructing client cache", "namespace", operatorNamespace)
		options.Cache.DefaultNamespaces = map[string]cache.Config{operatorNamespace: {}}
	case etc.SingleNamespace, etc.MultiNamespace:
		// Add support for SingleNamespace set in OPERATOR_NAMESPACE (e.g. `starboard-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `default`).
		// Add support for MultiNamespace set in OPERATOR_NAMESPACE (e.g. `starboard-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `default,kube-system`).
		// Note that you may face performance issues when using this mode with a high number of namespaces.
		// More: https://godoc.org/github.com/kubernetes-sigs/controller-runtime/pkg/cache#MultiNamespacedCacheBuilder
		namespaceCacheMap := make(map[string]cache.Config)
		setupLog.Info("Constructing client cache", "namespaces", targetNamespaces)
		for _, namespace := range append(targetNamespaces, operatorNamespace) {
			namespaceCacheMap[namespace] = cache.Config{}
		}
		options.Cache.DefaultNamespaces = namespaceCacheMap
	case etc.AllNamespaces:
		// Add support for AllNamespaces set in OPERATOR_NAMESPACE (e.g. `operators`)
		// and OPERATOR_TARGET_NAMESPACES left blank.
		setupLog.Info("Watching all namespaces")
	default:
		return fmt.Errorf("unrecognized install mode: %v", installMode)
	}

	kubeConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("getting kube client config: %w", err)
	}

	// The only reason we're using kubernetes.Clientset is that we need it to read Pod logs,
	// which is not supported by the client returned by the ctrl.Manager.
	kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("constructing kube client: %w", err)
	}

	mgr, err := ctrl.NewManager(kubeConfig, options)
	if err != nil {
		return fmt.Errorf("constructing controllers manager: %w", err)
	}

	err = mgr.AddReadyzCheck("ping", healthz.Ping)
	if err != nil {
		return err
	}

	err = mgr.AddHealthzCheck("ping", healthz.Ping)
	if err != nil {
		return err
	}

	configManager := starboard.NewConfigManager(kubeClientset, operatorNamespace)
	err = configManager.EnsureDefault(context.Background())
	if err != nil {
		return err
	}

	starboardConfig, err := configManager.Read(context.Background())
	if err != nil {
		return err
	}
	compatibleObjectMapper, err := kube.InitCompatibleMgr(mgr.GetClient().RESTMapper())
	if err != nil {
		return err
	}
	objectResolver := kube.NewObjectResolver(mgr.GetClient(), compatibleObjectMapper)
	limitChecker := controller.NewLimitChecker(operatorConfig, mgr.GetClient(), starboardConfig)
	logsReader := kube.NewLogsReader(kubeClientset)
	secretsReader := kube.NewSecretsReader(mgr.GetClient())

	if operatorConfig.VulnerabilityScannerEnabled {
		plugin, pluginContext, err := plugin.NewResolver().
			WithBuildInfo(buildInfo).
			WithNamespace(operatorNamespace).
			WithServiceAccountName(operatorConfig.ServiceAccount).
			WithConfig(starboardConfig).
			WithClient(mgr.GetClient()).
			GetVulnerabilityPlugin()
		if err != nil {
			return err
		}

		err = plugin.Init(pluginContext)
		if err != nil {
			return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
		}

		if err = (&vulnerabilityreport.WorkloadController{
			Logger:         ctrl.Log.WithName("reconciler").WithName("vulnerabilityreport"),
			Config:         operatorConfig,
			ConfigData:     starboardConfig,
			Client:         mgr.GetClient(),
			ObjectResolver: objectResolver,
			LimitChecker:   limitChecker,
			LogsReader:     logsReader,
			SecretsReader:  secretsReader,
			Plugin:         plugin,
			PluginContext:  pluginContext,
			ReadWriter:     vulnerabilityreport.NewReadWriter(&objectResolver),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup vulnerabilityreport reconciler: %w", err)
		}
	}

	// conditional check is handled inside SetupWithManager
	if err = (&controller.TTLReportReconciler{
		Logger: ctrl.Log.WithName("reconciler").WithName("ttlreport"),
		Config: operatorConfig,
		Client: mgr.GetClient(),
		Clock:  ext.NewSystemClock(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to setup TTLreport reconciler: %w", err)
	}

	if operatorConfig.ConfigAuditScannerEnabled {
		plugin, pluginContext, err := plugin.NewResolver().
			WithBuildInfo(buildInfo).
			WithNamespace(operatorNamespace).
			WithServiceAccountName(operatorConfig.ServiceAccount).
			WithConfig(starboardConfig).
			WithClient(mgr.GetClient()).
			GetConfigAuditPlugin()
		if err != nil {
			return err
		}

		err = plugin.Init(pluginContext)
		if err != nil {
			return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
		}

		if err = (&controller.ConfigAuditReportReconciler{
			Logger:         ctrl.Log.WithName("reconciler").WithName("configauditreport"),
			Config:         operatorConfig,
			ConfigData:     starboardConfig,
			Client:         mgr.GetClient(),
			ObjectResolver: objectResolver,
			LimitChecker:   limitChecker,
			LogsReader:     logsReader,
			Plugin:         plugin,
			PluginContext:  pluginContext,
			ReadWriter:     configauditreport.NewReadWriter(&objectResolver),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup configauditreport reconciler: %w", err)
		}

		if err = (&controller.PluginsConfigReconciler{
			Logger:        ctrl.Log.WithName("reconciler").WithName("pluginsconfig"),
			Config:        operatorConfig,
			Client:        mgr.GetClient(),
			Plugin:        plugin,
			PluginContext: pluginContext,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup %T: %w", controller.PluginsConfigReconciler{}, err)
		}
	}

	if operatorConfig.CISKubernetesBenchmarkEnabled {
		if err = (&controller.CISKubeBenchReportReconciler{
			Logger:       ctrl.Log.WithName("reconciler").WithName("ciskubebenchreport"),
			Config:       operatorConfig,
			ConfigData:   starboardConfig,
			Client:       mgr.GetClient(),
			LogsReader:   logsReader,
			LimitChecker: limitChecker,
			ReadWriter:   kubebench.NewReadWriter(mgr.GetClient()),
			Plugin:       kubebench.NewKubeBenchPlugin(ext.NewSystemClock(), starboardConfig),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup ciskubebenchreport reconciler: %w", err)
		}
	}

	if operatorConfig.ConfigAuditScannerBuiltIn {
		setupLog.Info("Enabling built-in configuration audit scanner")
		if err = (&configauditreport.ResourceController{
			Logger:         ctrl.Log.WithName("resourcecontroller"),
			Config:         operatorConfig,
			ConfigData:     starboardConfig,
			Client:         mgr.GetClient(),
			ObjectResolver: objectResolver,
			ReadWriter:     configauditreport.NewReadWriter(&objectResolver),
			BuildInfo:      buildInfo,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup resource controller: %w", err)
		}
	}

	if operatorConfig.ClusterComplianceEnabled {
		logger := ctrl.Log.WithName("reconciler").WithName("clustercompliancereport")
		cc := &compliance.ClusterComplianceReportReconciler{
			Logger: logger,
			Client: mgr.GetClient(),
			Mgr:    compliance.NewMgr(mgr.GetClient(), logger, starboardConfig),
			Clock:  ext.NewSystemClock(),
		}
		if err := cc.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup clustercompliancereport reconciler: %w", err)
		}
	}
	setupLog.Info("Starting controllers manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("starting controllers manager: %w", err)
	}

	return nil
}
