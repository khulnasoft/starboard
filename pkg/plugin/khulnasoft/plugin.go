package khulnasoft

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/starboard/pkg/docker"
	"github.com/khulnasoft/starboard/pkg/ext"
	"github.com/khulnasoft/starboard/pkg/kube"
	"github.com/khulnasoft/starboard/pkg/starboard"
	"github.com/khulnasoft/starboard/pkg/vulnerabilityreport"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Plugin the name of this plugin.
	khulnasoftPlugin = "Khulnasoft"

	keyKhulnasoftScannerImage   = "khulnasoft.imageRef"
	keyStarboardKhulnasoftImage = "khulnasoft.imageRefStarboardKhulnasoftScanner"
	keyKhulnasoftCommand        = "khulnasoft.command"
	keyKhulnasoftCspHost        = "khulnasoft.serverURL"
	keyKhulnasoftUsername       = "khulnasoft.username"
	keyKhulnasoftPassword       = "khulnasoft.password"
	keyKhulnasoftRegistry       = "khulnasoft.registry"

	keyResourcesRequestsCPU    = "khulnasoft.resources.requests.cpu"
	keyResourcesRequestsMemory = "khulnasoft.resources.requests.memory"
	keyResourcesLimitsCPU      = "khulnasoft.resources.limits.cpu"
	keyResourcesLimitsMemory   = "khulnasoft.resources.limits.memory"
)

// Command to scan image or filesystem.
type Command string

const (
	Filesystem Command = "filesystem"
	Image      Command = "image"
)

// Config defines configuration params for this plugin.
type Config struct {
	starboard.PluginConfig
}

func (c Config) GetCommand() (Command, error) {
	var ok bool
	var value string
	if value, ok = c.Data[keyKhulnasoftCommand]; !ok {
		// for backward compatibility, fallback to ImageScan
		return Image, nil
	}
	switch Command(value) {
	case Image:
		return Image, nil
	case Filesystem:
		return Filesystem, nil
	}
	return "", fmt.Errorf("invalid value (%s) of %s; allowed values (%s, %s)",
		value, keyKhulnasoftCommand, Image, Filesystem)
}

func (c Config) GetStarboardKhulnasoftScannerImage() (string, error) {
	var ok bool
	var value string
	if value, ok = c.Data[keyStarboardKhulnasoftImage]; !ok {
		return "", fmt.Errorf("property %s not set", keyStarboardKhulnasoftImage)
	}
	return value, nil
}

// GetResourceRequirements creates ResourceRequirements from the Config.
func (c Config) GetResourceRequirements() (corev1.ResourceRequirements, error) {
	requirements := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	err := c.setResourceLimit(keyResourcesRequestsCPU, &requirements.Requests, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}
	err = c.setResourceLimit(keyResourcesRequestsMemory, &requirements.Requests, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsCPU, &requirements.Limits, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsMemory, &requirements.Limits, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	return requirements, nil
}

func (c Config) setResourceLimit(configKey string, k8sResourceList *corev1.ResourceList, k8sResourceName corev1.ResourceName) error {
	if value, found := c.Data[configKey]; found {
		quantity, err := resource.ParseQuantity(value)
		if err != nil {
			return fmt.Errorf("parsing resource definition %s: %s %w", configKey, value, err)
		}

		(*k8sResourceList)[k8sResourceName] = quantity
	}
	return nil
}

type plugin struct {
	idGenerator ext.IDGenerator
	buildInfo   starboard.BuildInfo
}

// NewPlugin constructs a new vulnerabilityreport.Plugin, which is using
// the Khulnasoft Enterprise to scan container images of Kubernetes workloads.
func NewPlugin(
	idGenerator ext.IDGenerator,
	buildInfo starboard.BuildInfo,
) vulnerabilityreport.Plugin {
	return &plugin{
		idGenerator: idGenerator,
		buildInfo:   buildInfo,
	}
}

func (s *plugin) Init(_ starboard.PluginContext) error {
	// Do nothing
	return nil
}

func (s *plugin) GetScanJobSpec(ctx starboard.PluginContext, object client.Object,
	_ map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := s.newConfigFrom(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	command, err := config.GetCommand()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	switch command {
	case Image:
		return s.getPodSpecForImageCommand(ctx, config, object)
	case Filesystem:
		return s.getPodSpecForFileSystemCommand(ctx, config, object)
	default:
		return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized scanner command %q", command)

	}
}

func (s *plugin) getPodSpecForImageCommand(ctx starboard.PluginContext, config Config,
	object client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	spec, err := kube.GetPodSpec(object)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	initContainerName := s.idGenerator.GenerateID()

	khulnasoftImageRef, err := s.getImageRef(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	scanJobContainers := make([]corev1.Container, len(spec.Containers))
	for i, container := range spec.Containers {
		var err error
		scanJobContainers[i], err = s.newScanJobContainer(ctx, config, container)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
	}

	return corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		NodeName:                     spec.NodeName,
		Volumes: []corev1.Volume{
			{
				Name: "scannercli",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
			{
				Name: "dockersock",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/run/docker.sock",
					},
				},
			},
		},
		InitContainers: []corev1.Container{
			{
				Name:  initContainerName,
				Image: khulnasoftImageRef,
				Command: []string{
					"cp",
					"/opt/khulnasoft/scannercli",
					"/downloads/scannercli",
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "scannercli",
						MountPath: "/downloads",
					},
				},
			},
		},
		Containers: scanJobContainers,
	}, nil, nil
}

func (s *plugin) newScanJobContainer(ctx starboard.PluginContext, config Config,
	podContainer corev1.Container) (corev1.Container, error) {
	khulnasoftImageRef, err := s.getImageRef(ctx)
	if err != nil {
		return corev1.Container{}, err
	}
	version, err := starboard.GetVersionFromImageRef(khulnasoftImageRef)
	if err != nil {
		return corev1.Container{}, err
	}
	pluginConfigName := starboard.GetPluginConfigMapName(khulnasoftPlugin)

	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.Container{}, err
	}

	return corev1.Container{
		Name:                     podContainer.Name,
		Image:                    fmt.Sprintf("khulnasoft/starboard-scanner-khulnasoft:%s", s.buildInfo.Version),
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"/bin/sh",
			"-c",
			fmt.Sprintf("/usr/local/bin/starboard-scanner-khulnasoft --version $(KHULNASOFT_VERSION) "+
				"--host $(KHULNASOFT_CSP_HOST) --user $(KHULNASOFT_CSP_USERNAME) --password $(KHULNASOFT_CSP_PASSWORD) %s 2> %s",
				podContainer.Image,
				corev1.TerminationMessagePathDefault),
		},
		Env: []corev1.EnvVar{
			{
				Name:  "KHULNASOFT_VERSION",
				Value: version,
			},
			constructEnvVarSourceFromConfigMap("KHULNASOFT_CSP_HOST", pluginConfigName, keyKhulnasoftCspHost),
			constructEnvVarSourceFromConfigMap("KHULNASOFT_CSP_USERNAME", pluginConfigName, keyKhulnasoftUsername),
			constructEnvVarSourceFromConfigMap("KHULNASOFT_CSP_PASSWORD", pluginConfigName, keyKhulnasoftPassword),
		},
		Resources: requirements,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "scannercli",
				MountPath: "/usr/local/bin/scannercli",
				SubPath:   "scannercli",
			},
			{
				Name:      "dockersock",
				MountPath: "/var/run/docker.sock",
			},
		},
	}, nil
}

const (
	FsSharedVolumeName = "starboard-khulnasoft"
)

func (s *plugin) getPodSpecForFileSystemCommand(ctx starboard.PluginContext, config Config, object client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	spec, err := kube.GetPodSpec(object)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	initContainerName := s.idGenerator.GenerateID()

	khulnasoftImageRef, err := s.getImageRef(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	starboardKhulnasoftImage, err := config.GetStarboardKhulnasoftScannerImage()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	secretName := vulnerabilityreport.GetScanJobName(object) + "-volume"
	var env []corev1.EnvVar
	envVars, err := s.getEnvFromConfig(ctx, secretName)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	env = append(env, envVars...)
	scanJobContainers := make([]corev1.Container, len(spec.Containers))
	for i, container := range spec.Containers {
		var err error
		scanJobContainers[i], err = s.newScanJobContainerFSCommand(config, container, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
	}

	return corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: pointer.BoolPtr(false),
			Volumes: []corev1.Volume{
				{
					Name: FsSharedVolumeName,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumDefault,
						},
					},
				},
			},
			InitContainers: []corev1.Container{
				{
					Name:            initContainerName,
					Image:           khulnasoftImageRef,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command: []string{
						"cp",
						"/opt/khulnasoft/scannercli",
						"/var/khulnasoft/scannercli",
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      FsSharedVolumeName,
							MountPath: "/var/khulnasoft",
							ReadOnly:  false,
						},
					},
				},
				{
					Name:            s.idGenerator.GenerateID(),
					Image:           starboardKhulnasoftImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command: []string{
						"cp",
						"/usr/local/bin/starboard-scanner-khulnasoft",
						"/var/khulnasoft/starboard-scanner-khulnasoft",
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      FsSharedVolumeName,
							MountPath: "/var/khulnasoft",
							ReadOnly:  false,
						},
					},
				},
			},
			Containers: scanJobContainers,
		}, []*corev1.Secret{{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: ctx.GetNamespace(),
			},
			Data:       config.SecretData,
			StringData: config.Data,
		}}, nil
}

func (s *plugin) newScanJobContainerFSCommand(config Config, podContainer corev1.Container, envVars []corev1.EnvVar) (corev1.Container, error) {
	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.Container{}, err
	}
	return corev1.Container{
		Name:                     podContainer.Name,
		Image:                    podContainer.Image,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"/var/khulnasoft/starboard-scanner-khulnasoft",
		},
		Args: []string{
			"--version",
			"$(KHULNASOFT_VERSION)",
			"--host",
			"$(KHULNASOFT_CSP_HOST)",
			"--user",
			"$(KHULNASOFT_CSP_USERNAME)",
			"--password",
			"$(KHULNASOFT_CSP_PASSWORD)",
			"--command",
			"filesystem",
			"--registry",
			"$(KHULNASOFT_CSP_REGISTRY)",
			podContainer.Image,
		},
		Env:       envVars,
		Resources: requirements,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      FsSharedVolumeName,
				MountPath: "/var/khulnasoft",
				ReadOnly:  false,
			},
		},
	}, nil
}

func (s *plugin) ParseVulnerabilityReportData(_ starboard.PluginContext, _ string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityReportData, error) {
	var report v1alpha1.VulnerabilityReportData
	err := json.NewDecoder(logsReader).Decode(&report)
	return report, err
}

func (s *plugin) getImageRef(ctx starboard.PluginContext) (string, error) {
	config, err := ctx.GetConfig()
	if err != nil {
		return "", err
	}
	return config.GetRequiredData(keyKhulnasoftScannerImage)
}

func (s *plugin) newConfigFrom(ctx starboard.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{PluginConfig: pluginConfig}, nil
}

func (s *plugin) getEnvFromConfig(ctx starboard.PluginContext, secretName string) ([]corev1.EnvVar, error) {
	khulnasoftImageRef, err := s.getImageRef(ctx)
	if err != nil {
		return nil, err
	}
	version, err := starboard.GetVersionFromImageRef(khulnasoftImageRef)
	if err != nil {
		return nil, err
	}
	env := []corev1.EnvVar{
		{
			Name:  "KHULNASOFT_VERSION",
			Value: version,
		},
		constructEnvVarSourceFromSecret("KHULNASOFT_CSP_HOST", secretName, keyKhulnasoftCspHost),
		constructEnvVarSourceFromSecret("KHULNASOFT_CSP_USERNAME", secretName, keyKhulnasoftUsername),
		constructEnvVarSourceFromSecret("KHULNASOFT_CSP_PASSWORD", secretName, keyKhulnasoftPassword),
		constructEnvVarSourceFromSecret("KHULNASOFT_CSP_REGISTRY", secretName, keyKhulnasoftRegistry),
	}
	return env, nil
}

func constructEnvVarSourceFromConfigMap(envName, configMapName, key string) (res corev1.EnvVar) {
	return corev1.EnvVar{
		Name: envName,
		ValueFrom: &corev1.EnvVarSource{
			ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: configMapName,
				},
				Key:      key,
				Optional: pointer.BoolPtr(true),
			},
		},
	}
}

func constructEnvVarSourceFromSecret(envName, secretName, key string) (res corev1.EnvVar) {
	return corev1.EnvVar{
		Name: envName,
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: secretName,
				},
				Key:      key,
				Optional: pointer.BoolPtr(true),
			},
		},
	}
}
