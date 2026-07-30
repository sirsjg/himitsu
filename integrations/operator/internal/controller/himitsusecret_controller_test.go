package controller

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	himitsu "github.com/sirsjg/himitsu/integrations/client"
	himitsuv1alpha1 "github.com/sirsjg/himitsu/integrations/operator/api/v1alpha1"
)

const (
	testNamespace = "apps"
	testToken     = "himi_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// stubFetcher records the conditional-request versions it was asked for and
// returns scripted responses.
type stubFetcher struct {
	responses   []*himitsu.RuntimeConfig
	err         error
	calls       int
	seenVersion []int64
}

func (s *stubFetcher) RuntimeConfig(_ context.Context, _, _ string, knownVersion int64) (*himitsu.RuntimeConfig, error) {
	s.seenVersion = append(s.seenVersion, knownVersion)
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	index := s.calls - 1
	if index >= len(s.responses) {
		index = len(s.responses) - 1
	}
	return s.responses[index], nil
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("client-go scheme: %v", err)
	}
	if err := himitsuv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("himitsu scheme: %v", err)
	}
	return scheme
}

func authSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "himitsu-token", Namespace: testNamespace},
		// A trailing newline is what `kubectl create secret --from-file` produces.
		Data: map[string][]byte{"token": []byte(testToken + "\n")},
	}
}

func newHimitsuSecret(mutate func(*himitsuv1alpha1.HimitsuSecret)) *himitsuv1alpha1.HimitsuSecret {
	resource := &himitsuv1alpha1.HimitsuSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app-config", Namespace: testNamespace, Generation: 1,
		},
		Spec: himitsuv1alpha1.HimitsuSecretSpec{
			APIURL:          "https://himitsu.example.com",
			ProjectID:       "11111111-1111-1111-1111-111111111111",
			EnvironmentID:   "22222222-2222-2222-2222-222222222222",
			AuthSecretRef:   himitsuv1alpha1.SecretKeySelector{Name: "himitsu-token"},
			Target:          himitsuv1alpha1.TargetSpec{Name: "app-secrets"},
			RefreshInterval: metav1.Duration{Duration: time.Minute},
		},
	}
	if mutate != nil {
		mutate(resource)
	}
	return resource
}

// harness wires a reconciler over a fake cluster.
type harness struct {
	reconciler *HimitsuSecretReconciler
	k8s        client.Client
	fetcher    *stubFetcher
	resource   *himitsuv1alpha1.HimitsuSecret
}

func newHarness(t *testing.T, resource *himitsuv1alpha1.HimitsuSecret, fetcher *stubFetcher, extra ...client.Object) *harness {
	t.Helper()
	scheme := testScheme(t)
	objects := append([]client.Object{resource, authSecret()}, extra...)
	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithStatusSubresource(&himitsuv1alpha1.HimitsuSecret{}).
		Build()
	return &harness{
		reconciler: &HimitsuSecretReconciler{
			Client: k8s,
			Scheme: scheme,
			ClientFactory: func(string, string) (SecretFetcher, error) {
				return fetcher, nil
			},
		},
		k8s:      k8s,
		fetcher:  fetcher,
		resource: resource,
	}
}

func (h *harness) reconcile(t *testing.T) ctrl.Result {
	t.Helper()
	result, err := h.reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: h.resource.Name, Namespace: h.resource.Namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return result
}

func (h *harness) target(t *testing.T) *corev1.Secret {
	t.Helper()
	var secret corev1.Secret
	if err := h.k8s.Get(context.Background(), types.NamespacedName{
		Name: h.resource.Spec.Target.Name, Namespace: testNamespace,
	}, &secret); err != nil {
		t.Fatalf("get target secret: %v", err)
	}
	return &secret
}

func (h *harness) status(t *testing.T) himitsuv1alpha1.HimitsuSecretStatus {
	t.Helper()
	var resource himitsuv1alpha1.HimitsuSecret
	if err := h.k8s.Get(context.Background(), types.NamespacedName{
		Name: h.resource.Name, Namespace: h.resource.Namespace,
	}, &resource); err != nil {
		t.Fatalf("get resource: %v", err)
	}
	return resource.Status
}

func readyCondition(t *testing.T, status himitsuv1alpha1.HimitsuSecretStatus) metav1.Condition {
	t.Helper()
	for _, condition := range status.Conditions {
		if condition.Type == himitsuv1alpha1.ConditionReady {
			return condition
		}
	}
	t.Fatal("Ready condition not found")
	return metav1.Condition{}
}

func TestSyncCreatesSecret(t *testing.T) {
	h := newHarness(t, newHimitsuSecret(nil), &stubFetcher{responses: []*himitsu.RuntimeConfig{{
		ConfigVersion: 5,
		Secrets:       map[string]string{"DATABASE_URL": "postgres://db", "API_KEY": "k1"},
	}}})

	result := h.reconcile(t)
	if result.RequeueAfter != time.Minute {
		t.Fatalf("RequeueAfter = %v, want 1m", result.RequeueAfter)
	}

	secret := h.target(t)
	if string(secret.Data["DATABASE_URL"]) != "postgres://db" || string(secret.Data["API_KEY"]) != "k1" {
		t.Fatalf("data = %v", secret.Data)
	}
	if secret.Type != corev1.SecretTypeOpaque {
		t.Fatalf("type = %q", secret.Type)
	}
	if got := secret.Annotations["himitsu.io/config-version"]; got != "5" {
		t.Fatalf("config-version annotation = %q", got)
	}
	if got := secret.Labels["app.kubernetes.io/managed-by"]; got != "himitsu-operator" {
		t.Fatalf("managed-by = %q", got)
	}
	// Owner policy must set a controller reference so the Secret is garbage
	// collected with the HimitsuSecret.
	if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].Kind != "HimitsuSecret" {
		t.Fatalf("owner references = %+v", secret.OwnerReferences)
	}

	status := h.status(t)
	if status.ConfigVersion != 5 || status.SecretCount != 2 || status.ObservedGeneration != 1 {
		t.Fatalf("status = %+v", status)
	}
	if condition := readyCondition(t, status); condition.Status != metav1.ConditionTrue {
		t.Fatalf("Ready = %s (%s)", condition.Status, condition.Message)
	}
	if status.LastSyncTime == nil {
		t.Fatal("LastSyncTime not set")
	}
}

func TestTokenNewlineIsTrimmed(t *testing.T) {
	// Guards the real client's token format validation against the trailing
	// newline that kubectl adds.
	var gotToken string
	resource := newHimitsuSecret(nil)
	scheme := testScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(resource, authSecret()).
		WithStatusSubresource(&himitsuv1alpha1.HimitsuSecret{}).Build()
	reconciler := &HimitsuSecretReconciler{
		Client: k8s, Scheme: scheme,
		ClientFactory: func(_, token string) (SecretFetcher, error) {
			gotToken = token
			return &stubFetcher{responses: []*himitsu.RuntimeConfig{{ConfigVersion: 1, Secrets: map[string]string{"A": "1"}}}}, nil
		},
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: resource.Name, Namespace: resource.Namespace},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if gotToken != testToken {
		t.Fatalf("token = %q, want it trimmed", gotToken)
	}
}

func TestSecondReconcileSendsConditionalRequest(t *testing.T) {
	fetcher := &stubFetcher{responses: []*himitsu.RuntimeConfig{
		{ConfigVersion: 5, Secrets: map[string]string{"A": "1"}},
		{ConfigVersion: 5, NotModified: true},
	}}
	h := newHarness(t, newHimitsuSecret(nil), fetcher)

	h.reconcile(t)
	h.resource = mustReload(t, h)
	h.reconcile(t)

	if len(fetcher.seenVersion) != 2 {
		t.Fatalf("calls = %d, want 2", len(fetcher.seenVersion))
	}
	if fetcher.seenVersion[0] != 0 {
		t.Fatalf("first call knownVersion = %d, want 0 (unconditional)", fetcher.seenVersion[0])
	}
	if fetcher.seenVersion[1] != 5 {
		t.Fatalf("second call knownVersion = %d, want 5 (conditional)", fetcher.seenVersion[1])
	}
	// The 304 must leave the existing data intact rather than emptying it.
	if got := string(h.target(t).Data["A"]); got != "1" {
		t.Fatalf("data after 304 = %q, want preserved", got)
	}
	if status := h.status(t); status.SecretCount != 1 {
		t.Fatalf("SecretCount after 304 = %d, want 1", status.SecretCount)
	}
}

func TestDeletedTargetForcesFullRefetch(t *testing.T) {
	// The critical failure this prevents: someone deletes the Secret, the
	// operator sends a conditional request, gets 304, and never restores it.
	fetcher := &stubFetcher{responses: []*himitsu.RuntimeConfig{
		{ConfigVersion: 5, Secrets: map[string]string{"A": "1"}},
		{ConfigVersion: 5, Secrets: map[string]string{"A": "1"}},
	}}
	h := newHarness(t, newHimitsuSecret(nil), fetcher)
	h.reconcile(t)

	if err := h.k8s.Delete(context.Background(), h.target(t)); err != nil {
		t.Fatalf("delete target: %v", err)
	}
	h.resource = mustReload(t, h)
	h.reconcile(t)

	if fetcher.seenVersion[1] != 0 {
		t.Fatalf("knownVersion after target deletion = %d, want 0", fetcher.seenVersion[1])
	}
	if got := string(h.target(t).Data["A"]); got != "1" {
		t.Fatalf("target not restored, data = %q", got)
	}
}

func TestTamperedVersionStampForcesRefetch(t *testing.T) {
	// A hand-edited Secret whose version annotation no longer matches status
	// must be rewritten, not trusted.
	fetcher := &stubFetcher{responses: []*himitsu.RuntimeConfig{
		{ConfigVersion: 5, Secrets: map[string]string{"A": "1"}},
		{ConfigVersion: 5, Secrets: map[string]string{"A": "1"}},
	}}
	h := newHarness(t, newHimitsuSecret(nil), fetcher)
	h.reconcile(t)

	secret := h.target(t)
	secret.Annotations["himitsu.io/config-version"] = "999"
	if err := h.k8s.Update(context.Background(), secret); err != nil {
		t.Fatalf("update target: %v", err)
	}
	h.resource = mustReload(t, h)
	h.reconcile(t)

	if fetcher.seenVersion[1] != 0 {
		t.Fatalf("knownVersion after tampering = %d, want 0", fetcher.seenVersion[1])
	}
}

func TestSpecChangeForcesFullRefetch(t *testing.T) {
	// Pointing the resource at a different environment must not reuse the old
	// environment's config version.
	fetcher := &stubFetcher{responses: []*himitsu.RuntimeConfig{
		{ConfigVersion: 5, Secrets: map[string]string{"A": "1"}},
		{ConfigVersion: 2, Secrets: map[string]string{"B": "2"}},
	}}
	h := newHarness(t, newHimitsuSecret(nil), fetcher)
	h.reconcile(t)

	resource := mustReload(t, h)
	resource.Spec.EnvironmentID = "33333333-3333-3333-3333-333333333333"
	resource.Generation = 2
	if err := h.k8s.Update(context.Background(), resource); err != nil {
		t.Fatalf("update resource: %v", err)
	}
	h.resource = resource
	h.reconcile(t)

	if fetcher.seenVersion[1] != 0 {
		t.Fatalf("knownVersion after spec change = %d, want 0", fetcher.seenVersion[1])
	}
}

func TestOwnerPolicyRemovesDeletedKeys(t *testing.T) {
	fetcher := &stubFetcher{responses: []*himitsu.RuntimeConfig{
		{ConfigVersion: 1, Secrets: map[string]string{"KEEP": "a", "DROP": "b"}},
		{ConfigVersion: 2, Secrets: map[string]string{"KEEP": "a"}},
	}}
	h := newHarness(t, newHimitsuSecret(nil), fetcher)
	h.reconcile(t)
	h.resource = mustReload(t, h)
	h.reconcile(t)

	secret := h.target(t)
	if _, present := secret.Data["DROP"]; present {
		t.Fatal("key deleted upstream is still present under Owner policy")
	}
	if string(secret.Data["KEEP"]) != "a" {
		t.Fatalf("KEEP = %q", secret.Data["KEEP"])
	}
}

func TestMergePolicyPreservesForeignKeys(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "app-secrets", Namespace: testNamespace},
		Data:       map[string][]byte{"FOREIGN": []byte("keep-me")},
	}
	resource := newHimitsuSecret(func(r *himitsuv1alpha1.HimitsuSecret) {
		r.Spec.Target.CreationPolicy = himitsuv1alpha1.PolicyMerge
	})
	fetcher := &stubFetcher{responses: []*himitsu.RuntimeConfig{
		{ConfigVersion: 1, Secrets: map[string]string{"MANAGED": "v1", "TEMPORARY": "x"}},
		{ConfigVersion: 2, Secrets: map[string]string{"MANAGED": "v2"}},
	}}
	h := newHarness(t, resource, fetcher, existing)

	h.reconcile(t)
	h.resource = mustReload(t, h)
	h.reconcile(t)

	secret := h.target(t)
	if string(secret.Data["FOREIGN"]) != "keep-me" {
		t.Fatal("Merge policy destroyed a foreign key")
	}
	if string(secret.Data["MANAGED"]) != "v2" {
		t.Fatalf("MANAGED = %q", secret.Data["MANAGED"])
	}
	// A key we previously wrote and that upstream dropped must be removed.
	if _, present := secret.Data["TEMPORARY"]; present {
		t.Fatal("stale managed key survived under Merge policy")
	}
	// Merge must not take ownership, or deleting the HimitsuSecret would
	// garbage collect a Secret it does not own.
	if len(secret.OwnerReferences) != 0 {
		t.Fatalf("Merge policy set owner references: %+v", secret.OwnerReferences)
	}
}

func TestCacheSelectorLabelIsAlwaysApplied(t *testing.T) {
	// The manager caches only Secrets carrying this label. If a write ever omits
	// it, the operator stops observing that Secret and manual edits or deletions
	// go unnoticed until the next poll — so assert it under both policies,
	// including when adopting a pre-existing unlabelled Secret.
	for _, policy := range []himitsuv1alpha1.CreationPolicy{
		himitsuv1alpha1.PolicyOwner, himitsuv1alpha1.PolicyMerge,
	} {
		t.Run(string(policy), func(t *testing.T) {
			existing := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "app-secrets", Namespace: testNamespace},
				Data:       map[string][]byte{"PRE": []byte("existing")},
			}
			resource := newHimitsuSecret(func(r *himitsuv1alpha1.HimitsuSecret) {
				r.Spec.Target.CreationPolicy = policy
			})
			h := newHarness(t, resource, &stubFetcher{responses: []*himitsu.RuntimeConfig{{
				ConfigVersion: 1, Secrets: map[string]string{"A": "1"},
			}}}, existing)
			h.reconcile(t)

			if got := h.target(t).Labels[ManagedByLabel]; got != ManagedByValue {
				t.Fatalf("%s label = %q, want %q", ManagedByLabel, got, ManagedByValue)
			}
		})
	}
}

func TestDotenvTemplate(t *testing.T) {
	resource := newHimitsuSecret(func(r *himitsuv1alpha1.HimitsuSecret) {
		r.Spec.Target.Template = &himitsuv1alpha1.TemplateSpec{Format: himitsuv1alpha1.FormatDotenv}
	})
	h := newHarness(t, resource, &stubFetcher{responses: []*himitsu.RuntimeConfig{{
		ConfigVersion: 1, Secrets: map[string]string{"B_KEY": "two", "A_KEY": "one"},
	}}})
	h.reconcile(t)

	content := string(h.target(t).Data[".env"])
	// Deterministic ordering keeps the Secret from churning every reconcile.
	if content != "A_KEY=\"one\"\nB_KEY=\"two\"\n" {
		t.Fatalf("dotenv = %q", content)
	}
}

func TestDotenvTemplateEscapesValues(t *testing.T) {
	resource := newHimitsuSecret(func(r *himitsuv1alpha1.HimitsuSecret) {
		r.Spec.Target.Template = &himitsuv1alpha1.TemplateSpec{
			Format: himitsuv1alpha1.FormatDotenv, Key: "app.env",
		}
	})
	h := newHarness(t, resource, &stubFetcher{responses: []*himitsu.RuntimeConfig{{
		ConfigVersion: 1, Secrets: map[string]string{"TRICKY": "line1\nline2\"quoted\""},
	}}})
	h.reconcile(t)

	content := string(h.target(t).Data["app.env"])
	if strings.Count(content, "\n") != 1 {
		t.Fatalf("newline in value was not escaped: %q", content)
	}
	if !strings.Contains(content, `\"quoted\"`) {
		t.Fatalf("quotes not escaped: %q", content)
	}
}

func TestJsonTemplate(t *testing.T) {
	resource := newHimitsuSecret(func(r *himitsuv1alpha1.HimitsuSecret) {
		r.Spec.Target.Template = &himitsuv1alpha1.TemplateSpec{Format: himitsuv1alpha1.FormatJson}
	})
	h := newHarness(t, resource, &stubFetcher{responses: []*himitsu.RuntimeConfig{{
		ConfigVersion: 1, Secrets: map[string]string{"B": "2", "A": "1"},
	}}})
	h.reconcile(t)

	if got := string(h.target(t).Data["config.json"]); got != `{"A":"1","B":"2"}` {
		t.Fatalf("json = %q", got)
	}
}

func TestInvalidSecretKeyIsReportedNotSilentlyDropped(t *testing.T) {
	// Himitsu allows keys Kubernetes forbids in Secret data. Failing loudly
	// beats writing a partial Secret the workload will not notice is missing keys.
	h := newHarness(t, newHimitsuSecret(nil), &stubFetcher{responses: []*himitsu.RuntimeConfig{{
		ConfigVersion: 1, Secrets: map[string]string{"VALID": "a", "in valid!": "b"},
	}}})
	result := h.reconcile(t)

	if result.RequeueAfter != errorRequeue {
		t.Fatalf("RequeueAfter = %v, want %v", result.RequeueAfter, errorRequeue)
	}
	condition := readyCondition(t, h.status(t))
	if condition.Status != metav1.ConditionFalse || condition.Reason != himitsuv1alpha1.ReasonInvalidSpec {
		t.Fatalf("condition = %+v", condition)
	}
	if !strings.Contains(condition.Message, "in valid!") {
		t.Fatalf("message does not name the offending key: %q", condition.Message)
	}
	var secret corev1.Secret
	if err := h.k8s.Get(context.Background(), types.NamespacedName{
		Name: "app-secrets", Namespace: testNamespace,
	}, &secret); err == nil {
		t.Fatal("a partial Secret was written despite the invalid key")
	}
}

func TestMissingAuthSecretReportsAuthFailure(t *testing.T) {
	resource := newHimitsuSecret(func(r *himitsuv1alpha1.HimitsuSecret) {
		r.Spec.AuthSecretRef.Name = "absent"
	})
	h := newHarness(t, resource, &stubFetcher{})
	h.reconcile(t)

	condition := readyCondition(t, h.status(t))
	if condition.Status != metav1.ConditionFalse || condition.Reason != himitsuv1alpha1.ReasonAuthFailure {
		t.Fatalf("condition = %+v", condition)
	}
	if h.fetcher.calls != 0 {
		t.Fatal("API was called without a token")
	}
}

func TestMissingTokenKeyReportsAuthFailure(t *testing.T) {
	resource := newHimitsuSecret(func(r *himitsuv1alpha1.HimitsuSecret) {
		r.Spec.AuthSecretRef.Key = "wrong-key"
	})
	h := newHarness(t, resource, &stubFetcher{})
	h.reconcile(t)

	condition := readyCondition(t, h.status(t))
	if condition.Reason != himitsuv1alpha1.ReasonAuthFailure ||
		!strings.Contains(condition.Message, "wrong-key") {
		t.Fatalf("condition = %+v", condition)
	}
}

func TestUnauthorizedAPIErrorMapsToAuthFailure(t *testing.T) {
	h := newHarness(t, newHimitsuSecret(nil), &stubFetcher{
		err: &himitsu.Error{StatusCode: http.StatusUnauthorized, Code: "UNAUTHENTICATED", Message: "token revoked"},
	})
	h.reconcile(t)

	if condition := readyCondition(t, h.status(t)); condition.Reason != himitsuv1alpha1.ReasonAuthFailure {
		t.Fatalf("reason = %q, want AuthenticationFailure", condition.Reason)
	}
}

func TestGenericAPIErrorMapsToFetchFailure(t *testing.T) {
	h := newHarness(t, newHimitsuSecret(nil), &stubFetcher{err: errors.New("connection refused")})
	h.reconcile(t)

	condition := readyCondition(t, h.status(t))
	if condition.Reason != himitsuv1alpha1.ReasonFetchFailure {
		t.Fatalf("reason = %q, want FetchFailure", condition.Reason)
	}
	if !strings.Contains(condition.Message, "connection refused") {
		t.Fatalf("message = %q", condition.Message)
	}
}

func TestRefusesToStealAnotherResourcesTarget(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app-secrets", Namespace: testNamespace,
			Annotations: map[string]string{ownerAnnotation: "some-other-resource"},
		},
		Data: map[string][]byte{"THEIRS": []byte("v")},
	}
	h := newHarness(t, newHimitsuSecret(nil), &stubFetcher{responses: []*himitsu.RuntimeConfig{{
		ConfigVersion: 1, Secrets: map[string]string{"MINE": "v"},
	}}}, existing)
	h.reconcile(t)

	condition := readyCondition(t, h.status(t))
	if condition.Reason != himitsuv1alpha1.ReasonTargetConflict {
		t.Fatalf("reason = %q, want TargetConflict", condition.Reason)
	}
	if string(h.target(t).Data["THEIRS"]) != "v" {
		t.Fatal("another resource's Secret was overwritten")
	}
}

func TestZeroRefreshIntervalSyncsOnce(t *testing.T) {
	resource := newHimitsuSecret(func(r *himitsuv1alpha1.HimitsuSecret) {
		r.Spec.RefreshInterval = metav1.Duration{Duration: 0}
	})
	h := newHarness(t, resource, &stubFetcher{responses: []*himitsu.RuntimeConfig{{
		ConfigVersion: 1, Secrets: map[string]string{"A": "1"},
	}}})

	if result := h.reconcile(t); result.RequeueAfter != 0 {
		t.Fatalf("RequeueAfter = %v, want 0 (sync once)", result.RequeueAfter)
	}
}

func TestTemplateLabelsAndAnnotationsApplied(t *testing.T) {
	resource := newHimitsuSecret(func(r *himitsuv1alpha1.HimitsuSecret) {
		r.Spec.Target.Template = &himitsuv1alpha1.TemplateSpec{
			Labels:      map[string]string{"team": "platform"},
			Annotations: map[string]string{"reloader.stakater.com/match": "true"},
		}
	})
	h := newHarness(t, resource, &stubFetcher{responses: []*himitsu.RuntimeConfig{{
		ConfigVersion: 1, Secrets: map[string]string{"A": "1"},
	}}})
	h.reconcile(t)

	secret := h.target(t)
	if secret.Labels["team"] != "platform" {
		t.Fatalf("labels = %v", secret.Labels)
	}
	if secret.Annotations["reloader.stakater.com/match"] != "true" {
		t.Fatalf("annotations = %v", secret.Annotations)
	}
}

func TestDeletedResourceIsIgnored(t *testing.T) {
	scheme := testScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&himitsuv1alpha1.HimitsuSecret{}).Build()
	reconciler := &HimitsuSecretReconciler{Client: k8s, Scheme: scheme}

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "gone", Namespace: testNamespace},
	})
	if err != nil || result.RequeueAfter != 0 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestVersionStampOfRejectsGarbage(t *testing.T) {
	cases := map[string]int64{"": 0, "abc": 0, "12": 12, "-1": -1}
	for annotation, want := range cases {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{"himitsu.io/config-version": annotation},
		}}
		if got := versionStampOf(secret); got != want {
			t.Errorf("versionStampOf(%q) = %d, want %d", annotation, got, want)
		}
	}
	if got := versionStampOf(nil); got != 0 {
		t.Errorf("versionStampOf(nil) = %d", got)
	}
}

func TestValidSecretDataKey(t *testing.T) {
	valid := []string{"A", "a-b", "a_b", "a.b", "DATABASE_URL", "config.json", "9"}
	invalid := []string{"", ".", "..", "a b", "a/b", "a:b", "café", "a!"}
	for _, key := range valid {
		if !validSecretDataKey(key) {
			t.Errorf("validSecretDataKey(%q) = false, want true", key)
		}
	}
	for _, key := range invalid {
		if validSecretDataKey(key) {
			t.Errorf("validSecretDataKey(%q) = true, want false", key)
		}
	}
}

func TestConditionTransitionTimeIsStable(t *testing.T) {
	fetcher := &stubFetcher{responses: []*himitsu.RuntimeConfig{
		{ConfigVersion: 1, Secrets: map[string]string{"A": "1"}},
		{ConfigVersion: 1, NotModified: true},
	}}
	h := newHarness(t, newHimitsuSecret(nil), fetcher)
	h.reconcile(t)
	first := readyCondition(t, h.status(t)).LastTransitionTime

	h.resource = mustReload(t, h)
	h.reconcile(t)
	second := readyCondition(t, h.status(t)).LastTransitionTime

	if !first.Equal(&second) {
		t.Fatalf("LastTransitionTime moved without a status change: %v -> %v", first, second)
	}
}

func TestManagedKeysAnnotationIsRecorded(t *testing.T) {
	h := newHarness(t, newHimitsuSecret(nil), &stubFetcher{responses: []*himitsu.RuntimeConfig{{
		ConfigVersion: 1, Secrets: map[string]string{"B": "2", "A": "1"},
	}}})
	h.reconcile(t)

	if got := h.target(t).Annotations[managedKeysAnnotation]; got != "A,B" {
		t.Fatalf("managed keys = %q, want sorted \"A,B\"", got)
	}
}

func mustReload(t *testing.T, h *harness) *himitsuv1alpha1.HimitsuSecret {
	t.Helper()
	var resource himitsuv1alpha1.HimitsuSecret
	if err := h.k8s.Get(context.Background(), types.NamespacedName{
		Name: h.resource.Name, Namespace: h.resource.Namespace,
	}, &resource); err != nil {
		t.Fatalf("reload resource: %v", err)
	}
	return &resource
}

// Guards the assumption that config versions round-trip through the annotation
// as base-10 integers even at the upper end of the API's bigint range.
func TestVersionStampRoundTripsLargeValues(t *testing.T) {
	const large int64 = 9007199254740991
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{"himitsu.io/config-version": strconv.FormatInt(large, 10)},
	}}
	if got := versionStampOf(secret); got != large {
		t.Fatalf("versionStampOf = %d, want %d", got, large)
	}
}
