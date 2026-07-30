// Package controller reconciles HimitsuSecret resources into Kubernetes Secrets.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	himitsu "github.com/sirsjg/himitsu/integrations/client"
	himitsuv1alpha1 "github.com/sirsjg/himitsu/integrations/operator/api/v1alpha1"
)

const (
	// managedKeysAnnotation records which data keys this controller wrote, so a
	// Merge-policy sync can remove its own stale keys without touching keys that
	// belong to someone else.
	managedKeysAnnotation = "himitsu.io/managed-keys"

	// ownerAnnotation identifies the HimitsuSecret responsible for a target,
	// letting the controller refuse to fight another HimitsuSecret over the
	// same Secret.
	ownerAnnotation = "himitsu.io/owned-by"

	// errorRequeue paces retries after a failure that a later attempt may fix.
	errorRequeue = 30 * time.Second

	// defaultRefresh applies when RefreshInterval is unset.
	defaultRefresh = time.Minute
)

// ClientFactory builds a Himitsu API client. It is injectable so tests can run
// the reconciler against a stub without a live API.
type ClientFactory func(apiURL, token string) (SecretFetcher, error)

// SecretFetcher is the slice of the Himitsu client the controller needs.
type SecretFetcher interface {
	RuntimeConfig(ctx context.Context, projectID, environmentID string, knownVersion int64) (*himitsu.RuntimeConfig, error)
}

// DefaultClientFactory builds a real API client.
func DefaultClientFactory(apiURL, token string) (SecretFetcher, error) {
	return himitsu.New(apiURL, token, himitsu.WithUserAgent("himitsu-k8s-operator/1.0"))
}

// ManagedByLabel marks Secrets this operator writes. The manager's cache is
// restricted to Secrets carrying it, so a secrets operator does not hold every
// Secret in the cluster in memory.
const ManagedByLabel = "app.kubernetes.io/managed-by"

// ManagedByValue is the label value identifying this operator.
const ManagedByValue = "himitsu-operator"

// HimitsuSecretReconciler reconciles HimitsuSecret objects.
type HimitsuSecretReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClientFactory ClientFactory

	// APIReader performs uncached reads straight from the API server.
	//
	// The manager cache only holds Secrets labelled as ours, so credential
	// Secrets and not-yet-adopted Merge targets are invisible to it. Reading
	// those through the cache would report NotFound for objects that exist.
	// Falls back to the cached client when unset, which is what the tests use.
	APIReader client.Reader
}

// reader returns the uncached reader when available.
func (r *HimitsuSecretReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// +kubebuilder:rbac:groups=himitsu.io,resources=himitsusecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=himitsu.io,resources=himitsusecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=himitsu.io,resources=himitsusecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile drives one HimitsuSecret toward its desired state.
func (r *HimitsuSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource himitsuv1alpha1.HimitsuSecret
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		// A deleted HimitsuSecret needs no cleanup: Owner-policy targets are
		// garbage collected by their controller reference, and Merge-policy
		// targets are intentionally left behind.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	token, err := r.resolveToken(ctx, &resource)
	if err != nil {
		return r.fail(ctx, &resource, himitsuv1alpha1.ReasonAuthFailure, err)
	}

	api, err := r.factory()(resource.Spec.APIURL, token)
	if err != nil {
		// A malformed URL or token will not fix itself on a fast retry.
		return r.fail(ctx, &resource, himitsuv1alpha1.ReasonInvalidSpec, err)
	}

	// Decide whether we may use a conditional request. A conditional poll is
	// only safe when the target Secret genuinely holds the data for the version
	// we recorded; otherwise a 304 would leave a missing or stale Secret in
	// place forever.
	existing, targetExists, err := r.loadTarget(ctx, &resource)
	if err != nil {
		return r.fail(ctx, &resource, himitsuv1alpha1.ReasonWriteFailure, err)
	}
	if targetExists {
		if conflict := r.checkOwnership(&resource, existing); conflict != nil {
			return r.fail(ctx, &resource, himitsuv1alpha1.ReasonTargetConflict, conflict)
		}
	}

	knownVersion := int64(0)
	if targetExists &&
		resource.Status.ConfigVersion > 0 &&
		resource.Status.ObservedGeneration == resource.Generation &&
		versionStampOf(existing) == resource.Status.ConfigVersion {
		knownVersion = resource.Status.ConfigVersion
	}

	config, err := api.RuntimeConfig(ctx, resource.Spec.ProjectID, resource.Spec.EnvironmentID, knownVersion)
	if err != nil {
		reason := himitsuv1alpha1.ReasonFetchFailure
		if himitsu.IsUnauthorized(err) || himitsu.IsForbidden(err) {
			reason = himitsuv1alpha1.ReasonAuthFailure
		}
		return r.fail(ctx, &resource, reason, err)
	}

	if config.NotModified {
		logger.V(1).Info("environment unchanged", "configVersion", config.ConfigVersion)
		return r.succeed(ctx, &resource, config.ConfigVersion, resource.Status.SecretCount)
	}

	rendered, err := render(&resource, config.Secrets)
	if err != nil {
		return r.fail(ctx, &resource, himitsuv1alpha1.ReasonInvalidSpec, err)
	}

	if err := r.writeTarget(ctx, &resource, existing, targetExists, rendered, config.ConfigVersion); err != nil {
		if apierrors.IsConflict(err) {
			// Someone wrote the Secret between our read and our write. Retry
			// promptly rather than waiting out the error backoff.
			return ctrl.Result{Requeue: true}, nil
		}
		return r.fail(ctx, &resource, himitsuv1alpha1.ReasonWriteFailure, err)
	}

	logger.Info("synced secret",
		"target", resource.Spec.Target.Name,
		"keys", len(config.Secrets),
		"configVersion", config.ConfigVersion)
	return r.succeed(ctx, &resource, config.ConfigVersion, len(config.Secrets))
}

func (r *HimitsuSecretReconciler) factory() ClientFactory {
	if r.ClientFactory != nil {
		return r.ClientFactory
	}
	return DefaultClientFactory
}

// resolveToken reads the API token from the referenced Kubernetes Secret.
func (r *HimitsuSecretReconciler) resolveToken(ctx context.Context, resource *himitsuv1alpha1.HimitsuSecret) (string, error) {
	ref := resource.Spec.AuthSecretRef
	key := ref.Key
	if key == "" {
		key = "token"
	}

	var secret corev1.Secret
	name := types.NamespacedName{Namespace: resource.Namespace, Name: ref.Name}
	if err := r.reader().Get(ctx, name, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("auth secret %s not found", name)
		}
		return "", fmt.Errorf("reading auth secret %s: %w", name, err)
	}

	raw, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("auth secret %s has no key %q", name, key)
	}
	// Trailing newlines are near-universal when a token is created with
	// `kubectl create secret --from-file`, and would otherwise fail token
	// validation with a confusing "malformed" error.
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("auth secret %s key %q is empty", name, key)
	}
	return token, nil
}

func (r *HimitsuSecretReconciler) loadTarget(ctx context.Context, resource *himitsuv1alpha1.HimitsuSecret) (*corev1.Secret, bool, error) {
	var secret corev1.Secret
	name := types.NamespacedName{Namespace: resource.Namespace, Name: resource.Spec.Target.Name}
	if err := r.reader().Get(ctx, name, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("reading target secret %s: %w", name, err)
	}
	return &secret, true, nil
}

// checkOwnership refuses to write a Secret that a different HimitsuSecret
// already manages. Two resources fighting over one target would otherwise flap
// the Secret on every reconcile.
func (r *HimitsuSecretReconciler) checkOwnership(resource *himitsuv1alpha1.HimitsuSecret, existing *corev1.Secret) error {
	owner := existing.Annotations[ownerAnnotation]
	if owner == "" || owner == resource.Name {
		return nil
	}
	return fmt.Errorf("secret %s/%s is already managed by HimitsuSecret %q",
		existing.Namespace, existing.Name, owner)
}

// versionStampOf reads the config version the controller last stamped onto a
// target. A target written by an older operator, or edited by hand, reports 0
// and therefore forces a full re-fetch.
func versionStampOf(secret *corev1.Secret) int64 {
	if secret == nil {
		return 0
	}
	raw := secret.Annotations["himitsu.io/config-version"]
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0
	}
	return version
}

// render turns fetched secrets into Kubernetes Secret data according to the
// configured template.
func render(resource *himitsuv1alpha1.HimitsuSecret, secrets map[string]string) (map[string][]byte, error) {
	template := resource.Spec.Target.Template
	format := himitsuv1alpha1.FormatKeyValue
	templateKey := ""
	if template != nil {
		if template.Format != "" {
			format = template.Format
		}
		templateKey = template.Key
	}

	switch format {
	case himitsuv1alpha1.FormatKeyValue:
		data := make(map[string][]byte, len(secrets))
		for key, value := range secrets {
			if !validSecretDataKey(key) {
				return nil, fmt.Errorf(
					"secret key %q is not a valid Kubernetes Secret data key; use the Dotenv or Json template format for keys of this shape", key)
			}
			data[key] = []byte(value)
		}
		return data, nil

	case himitsuv1alpha1.FormatDotenv:
		if templateKey == "" {
			templateKey = ".env"
		}
		return map[string][]byte{templateKey: []byte(renderDotenv(secrets))}, nil

	case himitsuv1alpha1.FormatJson:
		if templateKey == "" {
			templateKey = "config.json"
		}
		// Marshal of a map sorts keys, so output is stable across reconciles and
		// does not churn the Secret's resourceVersion.
		encoded, err := json.Marshal(secrets)
		if err != nil {
			return nil, fmt.Errorf("rendering json template: %w", err)
		}
		return map[string][]byte{templateKey: encoded}, nil

	default:
		return nil, fmt.Errorf("unknown template format %q", format)
	}
}

// renderDotenv writes a deterministic .env document. Values are single-quoted
// with embedded quotes escaped, which round-trips through standard dotenv
// parsers including the one in packages/imports.
func renderDotenv(secrets map[string]string) string {
	keys := make([]string, 0, len(secrets))
	for key := range secrets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(strconv.Quote(secrets[key]))
		builder.WriteString("\n")
	}
	return builder.String()
}

// validSecretDataKey mirrors the Kubernetes restriction on Secret data keys:
// alphanumerics, '-', '_', and '.' only.
func validSecretDataKey(key string) bool {
	if key == "" || key == "." || key == ".." {
		return false
	}
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// writeTarget creates or updates the Kubernetes Secret.
//
// existing is the target as already read by loadTarget, so this does not re-read
// it. Updating that exact object means the API server rejects the write with a
// conflict if anyone changed it in between, which the caller retries.
func (r *HimitsuSecretReconciler) writeTarget(
	ctx context.Context,
	resource *himitsuv1alpha1.HimitsuSecret,
	existing *corev1.Secret,
	exists bool,
	rendered map[string][]byte,
	configVersion int64,
) error {
	target := resource.Spec.Target
	policy := target.CreationPolicy
	if policy == "" {
		policy = himitsuv1alpha1.PolicyOwner
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      target.Name,
			Namespace: resource.Namespace,
		},
	}
	if exists {
		secret = existing.DeepCopy()
	}

	managed := make([]string, 0, len(rendered))
	for key := range rendered {
		managed = append(managed, key)
	}
	sort.Strings(managed)

	err := func() error {
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		if secret.Labels == nil {
			secret.Labels = map[string]string{}
		}
		if template := target.Template; template != nil {
			for key, value := range template.Annotations {
				secret.Annotations[key] = value
			}
			for key, value := range template.Labels {
				secret.Labels[key] = value
			}
		}
		secret.Annotations[ownerAnnotation] = resource.Name
		secret.Annotations["himitsu.io/config-version"] = strconv.FormatInt(configVersion, 10)
		secret.Annotations["himitsu.io/project-id"] = resource.Spec.ProjectID
		secret.Annotations["himitsu.io/environment-id"] = resource.Spec.EnvironmentID
		// This label is also the manager cache's selector, so it must be set on
		// every target or the operator stops observing its own Secrets.
		secret.Labels[ManagedByLabel] = ManagedByValue

		if target.Type != "" {
			secret.Type = target.Type
		} else if secret.Type == "" {
			secret.Type = corev1.SecretTypeOpaque
		}

		switch policy {
		case himitsuv1alpha1.PolicyMerge:
			// Preserve foreign keys; drop only keys we wrote on a previous pass
			// and that upstream no longer has.
			if secret.Data == nil {
				secret.Data = map[string][]byte{}
			}
			for _, stale := range previouslyManaged(secret) {
				if _, current := rendered[stale]; !current {
					delete(secret.Data, stale)
				}
			}
			for key, value := range rendered {
				secret.Data[key] = value
			}

		default:
			// Owner: the rendered set is the whole truth, so a key deleted in
			// Himitsu disappears here too.
			secret.Data = rendered
			if err := controllerutil.SetControllerReference(resource, secret, r.Scheme); err != nil {
				return fmt.Errorf("setting controller reference: %w", err)
			}
		}

		secret.Annotations[managedKeysAnnotation] = strings.Join(managed, ",")
		return nil
	}()
	if err != nil {
		return fmt.Errorf("preparing secret %s/%s: %w", resource.Namespace, target.Name, err)
	}

	if exists {
		if err := r.Update(ctx, secret); err != nil {
			// Conflicts propagate unwrapped so the caller can recognise them and
			// requeue immediately.
			if apierrors.IsConflict(err) {
				return err
			}
			return fmt.Errorf("updating secret %s/%s: %w", resource.Namespace, target.Name, err)
		}
		return nil
	}
	if err := r.Create(ctx, secret); err != nil {
		// AlreadyExists means the Secret appeared between our read and this
		// write; treat it as a conflict so the next pass adopts it properly.
		if apierrors.IsAlreadyExists(err) {
			return apierrors.NewConflict(
				schema.GroupResource{Resource: "secrets"}, target.Name, err)
		}
		return fmt.Errorf("creating secret %s/%s: %w", resource.Namespace, target.Name, err)
	}
	return nil
}

func previouslyManaged(secret *corev1.Secret) []string {
	raw := secret.Annotations[managedKeysAnnotation]
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// succeed records a healthy sync and schedules the next poll.
func (r *HimitsuSecretReconciler) succeed(
	ctx context.Context,
	resource *himitsuv1alpha1.HimitsuSecret,
	configVersion int64,
	secretCount int,
) (ctrl.Result, error) {
	now := metav1.Now()
	resource.Status.ConfigVersion = configVersion
	resource.Status.SecretCount = secretCount
	resource.Status.LastSyncTime = &now
	resource.Status.ObservedGeneration = resource.Generation
	setCondition(resource, metav1.ConditionTrue, himitsuv1alpha1.ReasonSynced,
		fmt.Sprintf("Synced %d keys at config version %d", secretCount, configVersion))

	if err := r.Status().Update(ctx, resource); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{RequeueAfter: refreshInterval(resource)}, nil
}

// fail records the error on the resource and requeues.
//
// The error is deliberately not returned to controller-runtime: doing so would
// log it a second time and apply the manager's own backoff on top of ours.
func (r *HimitsuSecretReconciler) fail(
	ctx context.Context,
	resource *himitsuv1alpha1.HimitsuSecret,
	reason string,
	cause error,
) (ctrl.Result, error) {
	log.FromContext(ctx).Error(cause, "sync failed", "reason", reason)
	setCondition(resource, metav1.ConditionFalse, reason, cause.Error())
	resource.Status.ObservedGeneration = resource.Generation
	if err := r.Status().Update(ctx, resource); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{RequeueAfter: errorRequeue}, nil
}

func setCondition(resource *himitsuv1alpha1.HimitsuSecret, status metav1.ConditionStatus, reason, message string) {
	condition := metav1.Condition{
		Type:               himitsuv1alpha1.ConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: resource.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i, existing := range resource.Status.Conditions {
		if existing.Type != condition.Type {
			continue
		}
		// Preserve the original transition time when the status is unchanged,
		// so "how long has this been failing" stays answerable.
		if existing.Status == condition.Status {
			condition.LastTransitionTime = existing.LastTransitionTime
		}
		resource.Status.Conditions[i] = condition
		return
	}
	resource.Status.Conditions = append(resource.Status.Conditions, condition)
}

// refreshInterval resolves the poll cadence. A zero interval means sync once.
func refreshInterval(resource *himitsuv1alpha1.HimitsuSecret) time.Duration {
	interval := resource.Spec.RefreshInterval.Duration
	if interval < 0 {
		return defaultRefresh
	}
	return interval
}

// SetupWithManager registers the reconciler.
func (r *HimitsuSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&himitsuv1alpha1.HimitsuSecret{}).
		// Owns() makes a manual edit or deletion of an Owner-policy target
		// trigger an immediate re-sync rather than waiting for the next poll.
		Owns(&corev1.Secret{}).
		Complete(r)
}
