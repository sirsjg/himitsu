package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretKeySelector points at one key inside a Kubernetes Secret in the same
// namespace as the HimitsuSecret.
//
// Cross-namespace references are deliberately not supported: they would let any
// namespace owner mount a token they were never granted.
type SecretKeySelector struct {
	// Name of the Kubernetes Secret holding the credential.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Key within that Secret. Defaults to "token".
	// +kubebuilder:default=token
	// +optional
	Key string `json:"key,omitempty"`
}

// TemplateFormat controls how fetched secrets are rendered into the target.
// +kubebuilder:validation:Enum=KeyValue;Dotenv;Json
type TemplateFormat string

const (
	// FormatKeyValue writes one Secret data entry per Himitsu secret. This is
	// the default and the form that envFrom consumes directly.
	FormatKeyValue TemplateFormat = "KeyValue"

	// FormatDotenv renders every secret into a single .env-style blob stored
	// under Template.Key, for apps that load a file rather than the environment.
	FormatDotenv TemplateFormat = "Dotenv"

	// FormatJson renders a single JSON object under Template.Key.
	FormatJson TemplateFormat = "Json"
)

// CreationPolicy decides whether the operator owns the target Secret outright.
// +kubebuilder:validation:Enum=Owner;Merge
type CreationPolicy string

const (
	// PolicyOwner makes the operator the sole author of the target Secret: it
	// creates the Secret, sets a controller reference, and removes keys that no
	// longer exist upstream.
	PolicyOwner CreationPolicy = "Owner"

	// PolicyMerge patches managed keys into a Secret owned by something else and
	// leaves foreign keys untouched. No controller reference is set, so the
	// target survives deletion of the HimitsuSecret.
	PolicyMerge CreationPolicy = "Merge"
)

// TemplateSpec shapes the rendered Secret.
type TemplateSpec struct {
	// Format selects the rendering. Defaults to KeyValue.
	// +kubebuilder:default=KeyValue
	// +optional
	Format TemplateFormat `json:"format,omitempty"`

	// Key is the single Secret data key that Dotenv and Json formats write to.
	// Ignored by KeyValue. Defaults to ".env" for Dotenv and "config.json" for Json.
	// +optional
	Key string `json:"key,omitempty"`

	// Labels are merged onto the target Secret.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations are merged onto the target Secret.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// TargetSpec describes the Kubernetes Secret to maintain.
type TargetSpec struct {
	// Name of the Secret to create or maintain, in the HimitsuSecret's namespace.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Type of the created Secret. Defaults to Opaque.
	// +kubebuilder:default=Opaque
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`

	// CreationPolicy decides ownership of the target. Defaults to Owner.
	// +kubebuilder:default=Owner
	// +optional
	CreationPolicy CreationPolicy `json:"creationPolicy,omitempty"`

	// Template shapes the rendered data.
	// +optional
	Template *TemplateSpec `json:"template,omitempty"`
}

// HimitsuSecretSpec defines a sync from one Himitsu environment into one
// Kubernetes Secret.
type HimitsuSecretSpec struct {
	// APIURL is the base URL of the Himitsu API, e.g. https://himitsu.example.com.
	// +kubebuilder:validation:Pattern=`^https?://`
	APIURL string `json:"apiUrl"`

	// ProjectID is the Himitsu project UUID.
	// +kubebuilder:validation:MinLength=1
	ProjectID string `json:"projectId"`

	// EnvironmentID is the Himitsu environment UUID.
	// +kubebuilder:validation:MinLength=1
	EnvironmentID string `json:"environmentId"`

	// AuthSecretRef points at the Kubernetes Secret holding a Himitsu API token.
	// A read-only, environment-scoped token is strongly recommended: the
	// operator never writes back to Himitsu.
	AuthSecretRef SecretKeySelector `json:"authSecretRef"`

	// Target is the Kubernetes Secret to maintain.
	Target TargetSpec `json:"target"`

	// RefreshInterval is how often to poll for changes. Steady-state polls are
	// conditional requests that transfer no secret material and are answered
	// with 304, so a short interval is inexpensive. Defaults to 1m; set to 0 to
	// sync once and stop.
	// +kubebuilder:default="1m"
	// +optional
	RefreshInterval metav1.Duration `json:"refreshInterval,omitempty"`
}

// HimitsuSecretStatus reports observed sync state.
type HimitsuSecretStatus struct {
	// Conditions holds the standard Ready condition.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ConfigVersion is the Himitsu environment config version last written. It
	// is the value sent as If-None-Match on the next poll.
	// +optional
	ConfigVersion int64 `json:"configVersion,omitempty"`

	// SecretCount is how many keys were last written.
	// +optional
	SecretCount int `json:"secretCount,omitempty"`

	// LastSyncTime is when the target was last confirmed up to date, including
	// polls that returned 304.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ObservedGeneration is the spec generation this status reflects.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// Condition types and reasons reported by the controller.
const (
	// ConditionReady is true once the target Secret matches Himitsu.
	ConditionReady = "Ready"

	ReasonSynced         = "Synced"
	ReasonAuthFailure    = "AuthenticationFailure"
	ReasonFetchFailure   = "FetchFailure"
	ReasonWriteFailure   = "WriteFailure"
	ReasonInvalidSpec    = "InvalidSpec"
	ReasonTargetConflict = "TargetConflict"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=hsec,categories=himitsu
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.target.name`
// +kubebuilder:printcolumn:name="Keys",type=integer,JSONPath=`.status.secretCount`
// +kubebuilder:printcolumn:name="Version",type=integer,JSONPath=`.status.configVersion`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// HimitsuSecret syncs a Himitsu environment into a Kubernetes Secret.
type HimitsuSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HimitsuSecretSpec   `json:"spec,omitempty"`
	Status HimitsuSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HimitsuSecretList is a list of HimitsuSecret.
type HimitsuSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HimitsuSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HimitsuSecret{}, &HimitsuSecretList{})
}
