package k8s

// The few fields of the Kubernetes API objects the checks read. Everything else of a pod spec (environment
// values above all) is never decoded, so it cannot reach an output.

type ownerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type objectMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	Labels            map[string]string `json:"labels"`
	OwnerReferences   []ownerRef        `json:"ownerReferences"`
	CreationTimestamp string            `json:"creationTimestamp"`
}

type capabilities struct {
	Add []string `json:"add"`
}

type securityContext struct {
	Privileged   *bool         `json:"privileged"`
	Capabilities *capabilities `json:"capabilities"`
	RunAsNonRoot *bool         `json:"runAsNonRoot"`
	RunAsUser    *int64        `json:"runAsUser"`
}

type container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	SecurityContext *securityContext `json:"securityContext"`
}

type hostPath struct {
	Path string `json:"path"`
}

type volume struct {
	HostPath *hostPath `json:"hostPath"`
}

type podSpec struct {
	HostNetwork     bool             `json:"hostNetwork"`
	HostPID         bool             `json:"hostPID"`
	HostIPC         bool             `json:"hostIPC"`
	Volumes         []volume         `json:"volumes"`
	SecurityContext *securityContext `json:"securityContext"`
	Containers      []container      `json:"containers"`
	InitContainers  []container      `json:"initContainers"`
}

type containerStatus struct {
	Name    string `json:"name"`
	ImageID string `json:"imageID"`
}

type podStatus struct {
	Phase                 string            `json:"phase"`
	ContainerStatuses     []containerStatus `json:"containerStatuses"`
	InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
}

type pod struct {
	Metadata objectMeta `json:"metadata"`
	Spec     podSpec    `json:"spec"`
	Status   podStatus  `json:"status"`
}

type service struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Type     string            `json:"type"`
		Selector map[string]string `json:"selector"`
	} `json:"spec"`
}

type labelExpr struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type labelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []labelExpr       `json:"matchExpressions"`
}

type networkPolicy struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		PodSelector *labelSelector `json:"podSelector"`
	} `json:"spec"`
}

type policyRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

type role struct {
	Metadata objectMeta   `json:"metadata"`
	Rules    []policyRule `json:"rules"`
}

type subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type roleBinding struct {
	Kind     string     `json:"kind"`
	Metadata objectMeta `json:"metadata"`
	RoleRef  struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"roleRef"`
	Subjects []subject `json:"subjects"`
}

type policyResult struct {
	Policy *string `json:"policy"`
	Result string  `json:"result"`
}

type policyReport struct {
	Metadata objectMeta     `json:"metadata"`
	Results  []policyResult `json:"results"`
	Summary  orderedCounts  `json:"summary"`
}
