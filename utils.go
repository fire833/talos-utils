/*
*	Copyright (C) 2026 Kendall Tauser
*
*	This program is free software; you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*	This program is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*
*	You should have received a copy of the GNU General Public License along
*	with this program; if not, write to the Free Software Foundation, Inc.,
*	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package talosutils

import (
	"fmt"
	"net"
	"net/url"

	"github.com/siderolabs/crypto/x509"
	"github.com/siderolabs/talos/pkg/machinery/config/types/v1alpha1"
)

type MachineType string

const (
	Worker       MachineType = "worker"
	ControlPlane MachineType = "controlplane"
)

func NewNodeConfig(machine *v1alpha1.MachineConfig, cluster *v1alpha1.ClusterConfig) *v1alpha1.Config {
	f := false
	return &v1alpha1.Config{
		ConfigVersion: "v1alpha1",
		ConfigDebug:   &f,
		MachineConfig: machine,
		ClusterConfig: cluster,
	}
}

func NewMachineConfig(t MachineType, token, hostname string, disks []*v1alpha1.MachineDisk, net *v1alpha1.NetworkConfig, install *v1alpha1.InstallConfig,
	kubelet *v1alpha1.KubeletConfig, registries map[string]*v1alpha1.RegistryConfig, url string, port uint16,
	kernelModules []*v1alpha1.KernelModuleConfig, udevRules []string, ca *x509.PEMEncodedCertificateAndKey, additionalCas []*x509.PEMEncodedCertificate,
) *v1alpha1.MachineConfig {
	f := false
	return &v1alpha1.MachineConfig{
		MachineType:    string(t),
		MachineToken:   token,
		MachineDisks:   disks,
		MachineInstall: install,
		MachineNetwork: net,
		MachineUdev: &v1alpha1.UdevConfig{
			UdevRules: udevRules,
		},
		MachineCA:          ca,
		MachineAcceptedCAs: additionalCas,
		// MachineCertSANs:    []string{},
		MachineControlPlane: &v1alpha1.MachineControlPlaneConfig{
			MachineControllerManager: &v1alpha1.MachineControllerManagerConfig{
				MachineControllerManagerDisabled: &f,
			},
			MachineScheduler: &v1alpha1.MachineSchedulerConfig{
				MachineSchedulerDisabled: &f,
			},
		},
		MachineFiles: []*v1alpha1.MachineFile{},
		MachineTime: &v1alpha1.TimeConfig{
			TimeDisabled: &f,
		},
		MachineSystemDiskEncryption: &v1alpha1.SystemDiskEncryptionConfig{},
		MachineKubelet:              kubelet,
		MachineKernel: &v1alpha1.KernelConfig{
			KernelModules: kernelModules,
		},
		MachineNodeAnnotations: map[string]string{},
		MachineNodeTaints:      map[string]string{},
		MachineEnv:             v1alpha1.Env{},
		MachineRegistries: v1alpha1.RegistriesConfig{
			RegistryConfig: registries,
		},
		// MachinePods:                 []v1alpha1.Unstructured{},
	}
}

func NewTalosNetworkConfig(hostname string, devices []*v1alpha1.Device, nameservers, searchDomains []string) *v1alpha1.NetworkConfig {
	f := false
	return &v1alpha1.NetworkConfig{
		NetworkHostname:   hostname,
		NetworkInterfaces: devices,
		NameServers:       nameservers,
		Searches:          searchDomains,
		ExtraHostEntries:  []*v1alpha1.ExtraHost{},
		NetworkKubeSpan: &v1alpha1.NetworkKubeSpan{
			KubeSpanEnabled: &f,
		},
		NetworkDisableSearchDomain: &f,
	}
}

func NewTalosNICFixedIP(iface string, addresses []net.IP, mtu uint) *v1alpha1.Device {
	addrs := []string{}
	for _, ip := range addresses {
		addrs = append(addrs, ip.String())
	}

	return &v1alpha1.Device{
		DeviceInterface: iface,
		DeviceAddresses: addrs,
		DeviceMTU:       int(mtu),
	}
}

func NewTalosNICVIP(iface string, sharedIP net.IP, mtu uint) *v1alpha1.Device {
	return &v1alpha1.Device{
		DeviceInterface: iface,
		DeviceMTU:       int(mtu),
		DeviceVIPConfig: &v1alpha1.DeviceVIPConfig{
			SharedIP: sharedIP.String(),
		},
	}
}

func NewTalosDisk(dev string, partitions map[uint64]string) *v1alpha1.MachineDisk {
	partitionList := []*v1alpha1.DiskPartition{}

	for size, mountPoint := range partitions {
		partitionList = append(partitionList, &v1alpha1.DiskPartition{
			DiskSize:       v1alpha1.DiskSize(size),
			DiskMountPoint: mountPoint,
		})
	}

	return &v1alpha1.MachineDisk{
		DeviceName:     dev,
		DiskPartitions: partitionList,
	}
}

func newImage(image, tag string) string {
	return fmt.Sprintf("%s:%s", image, tag)
}

func NewTalosInstallConfig(image, tag, installDev string, kernelArgs []string, wipe bool) *v1alpha1.InstallConfig {
	legacyBIOS := false

	return &v1alpha1.InstallConfig{
		InstallDisk:              installDev,
		InstallExtraKernelArgs:   kernelArgs,
		InstallWipe:              &wipe,
		InstallImage:             newImage(image, tag),
		InstallLegacyBIOSSupport: &legacyBIOS,
	}
}

func NewTalosRegistryBasicAuth(user, password string, tlsSkipVerify bool) *v1alpha1.RegistryConfig {
	return &v1alpha1.RegistryConfig{
		RegistryTLS: &v1alpha1.RegistryTLSConfig{
			TLSInsecureSkipVerify: &tlsSkipVerify,
		},
		RegistryAuth: &v1alpha1.RegistryAuthConfig{
			RegistryUsername: user,
			RegistryPassword: password,
		},
	}
}

type EncryptionProvider string

const (
	LUKSProvider EncryptionProvider = "luks2"
)

func NewTalosDiskEncryptionConfig(provider EncryptionProvider) *v1alpha1.EncryptionConfig {
	return &v1alpha1.EncryptionConfig{
		EncryptionProvider: string(provider),
	}
}

func NewClusterConfigControlplane(endpoint *url.URL, name, id, secret, bootstrapToken, secretBoxKey string, net *v1alpha1.ClusterNetworkConfig,
	apiServer *v1alpha1.APIServerConfig, proxy *v1alpha1.ProxyConfig, controllerMgr *v1alpha1.ControllerManagerConfig,
	scheduler *v1alpha1.SchedulerConfig, etcd *v1alpha1.EtcdConfig, clusterCA, clusterAggregatorCA *x509.PEMEncodedCertificateAndKey, svcAcct *x509.PEMEncodedKey,
) *v1alpha1.ClusterConfig {
	return &v1alpha1.ClusterConfig{
		ClusterName:                      name,
		ClusterID:                        id,
		BootstrapToken:                   bootstrapToken,
		ClusterSecret:                    secret,
		ClusterSecretboxEncryptionSecret: secretBoxKey,
		ClusterCA:                        clusterCA,
		ClusterAggregatorCA:              clusterAggregatorCA,
		ClusterNetwork:                   net,
		ClusterServiceAccount:            svcAcct,
		ControlPlane: &v1alpha1.ControlPlaneConfig{
			Endpoint: &v1alpha1.Endpoint{URL: endpoint},
		},
		APIServerConfig:         apiServer,
		ProxyConfig:             proxy,
		ControllerManagerConfig: controllerMgr,
		SchedulerConfig:         scheduler,
		EtcdConfig:              etcd,
		ExtraManifests:          []string{},
		ExtraManifestHeaders:    map[string]string{},
		ClusterInlineManifests:  v1alpha1.ClusterInlineManifests{},
	}
}

func NewClusterConfigWorker(endpoint *url.URL, name, id, secret, bootstrapToken string, net *v1alpha1.ClusterNetworkConfig, clusterCA *x509.PEMEncodedCertificateAndKey) *v1alpha1.ClusterConfig {
	return &v1alpha1.ClusterConfig{
		ClusterName:    name,
		ClusterID:      id,
		BootstrapToken: bootstrapToken,
		ClusterSecret:  secret,
		ClusterCA:      &x509.PEMEncodedCertificateAndKey{Crt: clusterCA.Crt},
		ClusterNetwork: net,
		ControlPlane: &v1alpha1.ControlPlaneConfig{
			Endpoint: &v1alpha1.Endpoint{URL: endpoint},
		},
		ExtraManifests:         []string{},
		ExtraManifestHeaders:   map[string]string{},
		ClusterInlineManifests: v1alpha1.ClusterInlineManifests{},
	}
}

func NewTalosAPIServerConfig(image, tag string, endpoint *url.URL) *v1alpha1.APIServerConfig {
	t := true
	return &v1alpha1.APIServerConfig{
		ContainerImage: newImage(image, tag),
		CertSANs:       []string{endpoint.Hostname()},
		ExtraArgsConfig: map[string]string{
			"feature-gates": "UserNamespacesSupport=true,UserNamespacesPodSecurityStandards=true",
		},
		// Apparently, we need this: https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-admission-controller/
		AdmissionControlConfig: v1alpha1.AdmissionPluginConfigList{
			&v1alpha1.AdmissionPluginConfig{
				PluginName: "PodSecurity",
				PluginConfiguration: v1alpha1.Unstructured{
					Object: map[string]any{
						"apiVersion": "pod-security.admission.config.k8s.io/v1alpha1",
						"kind":       "PodSecurityConfiguration",
						"defaults": map[string]any{
							"audit":           "restricted",
							"audit-version":   "latest",
							"enforce":         "baseline",
							"enforce-version": "latest",
							"warn":            "restricted",
							"warn-version":    "latest",
						},
						"exemptions": map[string]any{
							"namespaces":     []string{"kube-system"},
							"runtimeClasses": []string{},
							"usernames":      []string{},
						},
					},
				},
			},
		},
		// We definitely want to disable PSP, its been removed for a long while iirc.
		DisablePodSecurityPolicyConfig: &t,
		// Maybe we don't need this?
		AuditPolicyConfig: v1alpha1.Unstructured{},
	}
}

func NewTalosKubeProxyConfig(image, tag string) *v1alpha1.ProxyConfig {
	return &v1alpha1.ProxyConfig{
		ContainerImage: newImage(image, tag),
	}
}

func NewTalosControllerManagerConfig(image, tag string) *v1alpha1.ControllerManagerConfig {
	return &v1alpha1.ControllerManagerConfig{
		ContainerImage: newImage(image, tag),
	}
}

func NewTalosSchedulerConfig(image, tag string) *v1alpha1.SchedulerConfig {
	return &v1alpha1.SchedulerConfig{
		ContainerImage: newImage(image, tag),
	}
}

func NewTalosEtcdConfig(image, tag string, rootCa *x509.PEMEncodedCertificateAndKey) *v1alpha1.EtcdConfig {
	return &v1alpha1.EtcdConfig{
		ContainerImage: newImage(image, tag),
		RootCA:         rootCa,
	}
}

func NewTalosKubeletConfig(image, tag string) *v1alpha1.KubeletConfig {
	return &v1alpha1.KubeletConfig{
		KubeletImage: newImage(image, tag),
		KubeletExtraConfig: v1alpha1.Unstructured{
			Object: map[string]any{
				"featureGates": map[string]any{
					"UserNamespacesSupport":              true,
					"UserNamespacesPodSecurityStandards": true,
				},
			},
		},
	}
}

func NewTalosClusterNetworkConfigCNI(cni *v1alpha1.CNIConfig, clusterDNS string, podSubnet, serviceSubnet []string) *v1alpha1.ClusterNetworkConfig {
	return &v1alpha1.ClusterNetworkConfig{
		CNI:           cni,
		DNSDomain:     clusterDNS,
		PodSubnet:     podSubnet,
		ServiceSubnet: serviceSubnet,
	}
}

func NewTalosClusterNetworkConfig(clusterDNS string, podSubnet, serviceSubnet []string) *v1alpha1.ClusterNetworkConfig {
	return &v1alpha1.ClusterNetworkConfig{
		DNSDomain:     clusterDNS,
		PodSubnet:     podSubnet,
		ServiceSubnet: serviceSubnet,
	}
}

func NewTalosCNIConfigCustom(manifestUrls []string) *v1alpha1.CNIConfig {
	return &v1alpha1.CNIConfig{
		CNIName: "custom",
		CNIUrls: manifestUrls,
	}
}

func NewTalosCNINone() *v1alpha1.CNIConfig {
	return &v1alpha1.CNIConfig{
		CNIName: "none",
		CNIUrls: []string{},
	}
}

func NewTalosCNIConfigCalico() *v1alpha1.CNIConfig {
	return NewTalosCNIConfigCustom([]string{"https://raw.githubusercontent.com/projectcalico/calico/v3.29.2/manifests/calico.yaml"})
}
