// Offline tests for the AKS security baseline policies.
//
// envtest starts a real kube-apiserver + etcd (Kubernetes 1.37 by default). Every
// manifest in ../policies and ../workloads is created exactly as Flux or kubectl would,
// and the tests then act as a tenant (impersonated user "alice", cluster-admin via RBAC
// but NOT system:masters) to prove what Pod Security Admission, the
// ValidatingAdmissionPolicies and the MutatingAdmissionPolicy actually do.
package sectest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

var (
	ctx    = context.Background()
	admin  client.Client         // system:masters (envtest default)
	tenant *kubernetes.Clientset // impersonated "alice": cluster-admin via RBAC only
	tcr    client.Client         // same identity, generic client
	approv *kubernetes.Clientset // member of the approved exception group
	warns  = &warningLog{}
)

type warningLog struct{ msgs []string }

func (w *warningLog) HandleWarningHeader(_ int, _ string, msg string) { w.msgs = append(w.msgs, msg) }
func (w *warningLog) take() []string                                  { m := w.msgs; w.msgs = nil; return m }

func TestMain(m *testing.M) {
	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest start:", err, "\n(run via ./run.sh)")
		os.Exit(1)
	}
	code := func() int {
		defer func() { _ = env.Stop() }()
		if admin, err = client.New(cfg, client.Options{}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		must(bootstrap())

		tcfg := rest.CopyConfig(cfg)
		tcfg.Impersonate = rest.ImpersonationConfig{UserName: "alice", Groups: []string{"team-payments", "system:authenticated"}}
		tcfg.WarningHandler = warns
		tenant = kubernetes.NewForConfigOrDie(tcfg)
		if tcr, err = client.New(tcfg, client.Options{}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		acfg := rest.CopyConfig(cfg)
		acfg.Impersonate = rest.ImpersonationConfig{UserName: "bob", Groups: []string{"aks-nodes-proxy-approvers", "system:authenticated"}}
		approv = kubernetes.NewForConfigOrDie(acfg)

		must(waitForPolicies())
		return m.Run()
	}()
	os.Exit(code)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// bootstrap applies policies and workloads' prerequisites as the platform (system:masters).
func bootstrap() error {
	for _, ns := range []string{"team-a", "restricted-only", "plain"} {
		labels := map[string]string{}
		if ns == "restricted-only" {
			labels["pod-security.kubernetes.io/enforce"] = "restricted"
			labels["pod-security.kubernetes.io/enforce-version"] = "latest"
		}
		if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: labels}}); err != nil {
			return err
		}
	}
	files, _ := filepath.Glob("../policies/*.yaml")
	for _, f := range files {
		if err := applyFile(admin, f); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
	}
	// No ServiceAccount controller in envtest: create the "default" accounts pods use.
	for _, ns := range []string{"payments", "team-a", "restricted-only", "plain", "kube-system"} {
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: ns}}
		if err := admin.Create(ctx, sa); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}
	// alice is a cluster-admin through RBAC (as she would be through Azure RBAC on AKS)
	// but is not in system:masters, so admission policies apply to her.
	for _, u := range []string{"alice", "bob"} {
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: u + "-admin"},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: u}},
		}
		if err := admin.Create(ctx, crb); err != nil {
			return err
		}
	}
	return nil
}

func applyFile(c client.Client, path string) error {
	objs, err := readObjects(path)
	if err != nil {
		return err
	}
	for _, o := range objs {
		if err := c.Create(ctx, o); err != nil {
			return fmt.Errorf("%s/%s: %w", o.GetKind(), o.GetName(), err)
		}
	}
	return nil
}

func readObjects(path string) ([]*unstructured.Unstructured, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*unstructured.Unstructured
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	for {
		u := &unstructured.Unstructured{}
		if err := dec.Decode(&u.Object); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		if len(u.Object) > 0 {
			out = append(out, u)
		}
	}
}

// Admission policies are compiled asynchronously; wait until each one is enforcing.
func waitForPolicies() error {
	probes := map[string]func() error{
		"deny-nodes-proxy-grants": func() error {
			_, err := tenant.RbacV1().ClusterRoles().Create(ctx, proxyRole("probe", "nodes/proxy"), metav1.CreateOptions{DryRun: []string{"All"}})
			return err
		},
		"deny-service-externalips": func() error {
			_, err := tenant.CoreV1().Services("plain").Create(ctx, svc("probe", "203.0.113.10"), metav1.CreateOptions{DryRun: []string{"All"}})
			return err
		},
		"require-user-namespaces": func() error {
			_, err := tenant.CoreV1().Pods("payments").Create(ctx, restrictedPod("probe", nil), metav1.CreateOptions{DryRun: []string{"All"}})
			return err
		},
	}
	deadline := time.Now().Add(60 * time.Second)
	for name, probe := range probes {
		for {
			if err := probe(); err != nil && strings.Contains(err.Error(), name) {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("policy %s never started enforcing", name)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	for {
		p, err := tenant.CoreV1().Pods("plain").Create(ctx, plainPod("probe"), metav1.CreateOptions{DryRun: []string{"All"}})
		if err == nil && p.Spec.SecurityContext != nil && p.Spec.SecurityContext.SeccompProfile != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("MutatingAdmissionPolicy pod-secure-defaults never started mutating (last err: %v)", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// ---------------------------------------------------------------- fixtures

func plainPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry.example/app:1"}}},
	}
}

// restrictedPod is compliant with PSS restricted, with hostUsers as given (nil = unset).
func restrictedPod(name string, hostUsers *bool) *corev1.Pod {
	p := plainPod(name)
	p.Spec.HostUsers = hostUsers
	p.Spec.SecurityContext = &corev1.PodSecurityContext{
		RunAsNonRoot:   ptr.To(true),
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
	return p
}

func proxyRole(name string, resources ...string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: resources, Verbs: []string{"get"}}},
	}
}

func svc(name string, externalIPs ...string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.ServiceSpec{
			Selector:    map[string]string{"app": name},
			Ports:       []corev1.ServicePort{{Port: 80}},
			ExternalIPs: externalIPs,
		},
	}
}

func expectDenied(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected request to be denied (%q), it was admitted", contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("expected denial containing %q, got: %v", contains, err)
	}
	t.Logf("denied as expected: %v", err)
}

func expectAdmitted(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected request to be admitted, got: %v", err)
	}
}

// ---------------------------------------------------------------- pod isolation

func TestPSSRestrictedRejectsPrivilegedPod(t *testing.T) {
	p := plainPod("privileged")
	p.Spec.HostUsers = ptr.To(false)
	p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: ptr.To(true)}
	_, err := tenant.CoreV1().Pods("payments").Create(ctx, p, metav1.CreateOptions{})
	expectDenied(t, err, `violates PodSecurity "restricted:latest"`)
}

func TestHardenedWorkloadIsAdmitted(t *testing.T) {
	objs, err := readObjects("../workloads/hardened-deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var podSpec map[string]any
	warns.take()
	for _, o := range objs {
		expectAdmitted(t, tcr.Create(ctx, o))
		if o.GetKind() == "Deployment" {
			podSpec, _, _ = unstructured.NestedMap(o.Object, "spec", "template", "spec")
		}
	}
	if w := warns.take(); len(w) > 0 {
		t.Errorf("hardened workload produced warnings: %v", w)
	}
	// Deployments are not checked by PSA enforce; create a Pod from the template to prove it.
	raw, _ := yaml.Marshal(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "checkout-probe"}, "spec": podSpec})
	pod := &corev1.Pod{}
	if err := yaml.Unmarshal(raw, pod); err != nil {
		t.Fatal(err)
	}
	got, err := tenant.CoreV1().Pods("payments").Create(ctx, pod, metav1.CreateOptions{})
	expectAdmitted(t, err)
	if got.Spec.HostUsers == nil || *got.Spec.HostUsers {
		t.Errorf("hostUsers lost: %v", got.Spec.HostUsers)
	}
	if ap := got.Spec.SecurityContext.AppArmorProfile; ap == nil || ap.Type != corev1.AppArmorProfileTypeRuntimeDefault {
		t.Errorf("appArmorProfile lost: %+v", ap)
	}
}

func TestUserNamespacesRequiredByLabel(t *testing.T) {
	_, err := tenant.CoreV1().Pods("payments").Create(ctx, restrictedPod("no-userns", nil), metav1.CreateOptions{})
	expectDenied(t, err, "must set spec.hostUsers: false")

	_, err = tenant.CoreV1().Pods("payments").Create(ctx, restrictedPod("host-userns", ptr.To(true)), metav1.CreateOptions{})
	expectDenied(t, err, "must set spec.hostUsers: false")

	// The same pod is fine in a namespace that hasn't opted in.
	_, err = tenant.CoreV1().Pods("restricted-only").Create(ctx, restrictedPod("no-userns", nil), metav1.CreateOptions{})
	expectAdmitted(t, err)
}

func TestUserNamespacesRejectHostNamespaces(t *testing.T) {
	p := plainPod("userns-hostnet")
	p.Spec.HostUsers = ptr.To(false)
	p.Spec.HostNetwork = true
	_, err := tenant.CoreV1().Pods("plain").Create(ctx, p, metav1.CreateOptions{})
	if !apierrors.IsInvalid(err) {
		t.Fatalf("expected API validation error for hostUsers=false + hostNetwork, got %v", err)
	}
	t.Logf("rejected by API validation: %v", err)
}

// Finding: does PSS "restricted" relax runAsNonRoot for pods in a user namespace?
func TestPSSRestrictedWithUserNamespaceAndRootUID(t *testing.T) {
	p := restrictedPod("userns-root", ptr.To(false))
	p.Spec.SecurityContext.RunAsNonRoot = nil
	p.Spec.SecurityContext.RunAsUser = ptr.To[int64](0)
	_, errUserNS := tenant.CoreV1().Pods("restricted-only").Create(ctx, p, metav1.CreateOptions{})

	q := restrictedPod("hostns-root", nil)
	q.Spec.SecurityContext.RunAsNonRoot = nil
	q.Spec.SecurityContext.RunAsUser = ptr.To[int64](0)
	_, errHost := tenant.CoreV1().Pods("restricted-only").Create(ctx, q, metav1.CreateOptions{})

	t.Logf("FINDING restricted + hostUsers=false + runAsUser=0: err=%v", errUserNS)
	t.Logf("FINDING restricted + host user ns   + runAsUser=0: err=%v", errHost)
	if errHost == nil {
		t.Fatal("root in the host user namespace must be rejected by restricted")
	}
	if errUserNS != nil {
		t.Fatalf("expected PSS restricted to accept UID 0 inside a user namespace on 1.33+, got %v", errUserNS)
	}
}

// gitRepo (CVE-2024-10220) is permanently disabled in the kubelet from 1.36, but the API
// server still admits the field with only a warning. The pod then fails on the node.
// Pod Security "restricted" (allowed volume types) is what stops it at the front door.
func TestGitRepoVolume(t *testing.T) {
	p := restrictedPod("gitrepo", nil)
	p.Spec.Volumes = []corev1.Volume{{Name: "src", VolumeSource: corev1.VolumeSource{GitRepo: &corev1.GitRepoVolumeSource{Repository: "https://example.invalid/repo.git"}}}}

	warns.take()
	_, err := tenant.CoreV1().Pods("plain").Create(ctx, p, metav1.CreateOptions{})
	w := warns.take()
	t.Logf("FINDING gitRepo without PSS: err=%v warnings=%v", err, w)
	expectAdmitted(t, err)
	if !strings.Contains(strings.Join(w, " "), "gitRepo") {
		t.Errorf("expected a gitRepo deprecation warning, got %v", w)
	}

	p.Name = "gitrepo-restricted"
	_, err = tenant.CoreV1().Pods("restricted-only").Create(ctx, p, metav1.CreateOptions{})
	expectDenied(t, err, "restricted volume types")
}

// ---------------------------------------------------------------- mutating defaults

func TestMAPFillsSecureDefaults(t *testing.T) {
	got, err := tenant.CoreV1().Pods("team-a").Create(ctx, plainPod("defaults"), metav1.CreateOptions{})
	expectAdmitted(t, err)
	if got.Spec.AutomountServiceAccountToken == nil || *got.Spec.AutomountServiceAccountToken {
		t.Errorf("automountServiceAccountToken = %v, want false", got.Spec.AutomountServiceAccountToken)
	}
	if sc := got.Spec.SecurityContext; sc == nil || sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("seccompProfile not defaulted: %+v", sc)
	}
	// No projected token volume was injected because automount is now false.
	for _, v := range got.Spec.Volumes {
		if v.Projected != nil {
			t.Errorf("unexpected projected SA token volume %q", v.Name)
		}
	}
}

func TestMAPKeepsExplicitChoices(t *testing.T) {
	p := plainPod("explicit")
	p.Spec.AutomountServiceAccountToken = ptr.To(true)
	p.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsUser: ptr.To[int64](1000)}
	got, err := tenant.CoreV1().Pods("team-a").Create(ctx, p, metav1.CreateOptions{})
	expectAdmitted(t, err)
	if !*got.Spec.AutomountServiceAccountToken {
		t.Error("explicit automountServiceAccountToken: true was overwritten")
	}
	if got.Spec.SecurityContext.RunAsUser == nil || *got.Spec.SecurityContext.RunAsUser != 1000 {
		t.Error("existing securityContext was replaced instead of extended")
	}
	if got.Spec.SecurityContext.SeccompProfile == nil {
		t.Error("seccompProfile not added to an existing securityContext")
	}
}

func TestMAPSkipsSystemNamespaces(t *testing.T) {
	pod, err := tenant.CoreV1().Pods("kube-system").Create(ctx, plainPod("untouched"), metav1.CreateOptions{})
	expectAdmitted(t, err)
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
		t.Error("kube-system pod was mutated")
	}
}

// Mutation runs before Pod Security Admission: a pod that only forgot seccomp passes restricted.
func TestMAPRunsBeforePodSecurity(t *testing.T) {
	p := restrictedPod("forgot-seccomp", nil)
	p.Spec.SecurityContext.SeccompProfile = nil
	_, err := tenant.CoreV1().Pods("restricted-only").Create(ctx, p, metav1.CreateOptions{})
	expectAdmitted(t, err)
}

// ---------------------------------------------------------------- control-plane access

func TestNodesProxyGrantsDenied(t *testing.T) {
	cases := map[string]*rbacv1.ClusterRole{
		"nodes-proxy":  proxyRole("legacy-scraper", "nodes/proxy"),
		"nodes-wild":   proxyRole("nodes-wild", "nodes/*"),
		"all-wildcard": {ObjectMeta: metav1.ObjectMeta{Name: "god-mode"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}},
	}
	for name, cr := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := tenant.RbacV1().ClusterRoles().Create(ctx, cr, metav1.CreateOptions{})
			expectDenied(t, err, "grants nodes/proxy")
		})
	}
	t.Run("namespaced-role", func(t *testing.T) {
		r := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "sneaky"}, Rules: proxyRole("x", "nodes/proxy").Rules}
		_, err := tenant.RbacV1().Roles("team-a").Create(ctx, r, metav1.CreateOptions{})
		expectDenied(t, err, "grants nodes/proxy")
	})
	t.Run("bind-sa-to-kubelet-api-admin", func(t *testing.T) {
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "agent-kubelet-admin"},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "system:kubelet-api-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "agent", Namespace: "team-a"}},
		}
		_, err := tenant.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{})
		expectDenied(t, err, "binds a service account to system:kubelet-api-admin")
	})
	t.Run("approved-group-exception", func(t *testing.T) {
		_, err := approv.RbacV1().ClusterRoles().Create(ctx, proxyRole("approved-debugger", "nodes/proxy"), metav1.CreateOptions{})
		expectAdmitted(t, err)
	})
}

func TestFineGrainedKubeletRolesAllowed(t *testing.T) {
	objs, err := readObjects("../policies/rbac-kubelet-readers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objs {
		o.SetName(o.GetName() + "-tenant")
		expectAdmitted(t, tcr.Create(ctx, o))
	}
	// The apiserver's bootstrap role carries the fine-grained subresources on 1.36+.
	cr := &rbacv1.ClusterRole{}
	if err := admin.Get(ctx, client.ObjectKey{Name: "system:kubelet-api-admin"}, cr); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, r := range cr.Rules {
		for _, res := range r.Resources {
			have[res] = true
		}
	}
	for _, want := range []string{"nodes/proxy", "nodes/metrics", "nodes/stats", "nodes/log", "nodes/pods", "nodes/healthz", "nodes/configz"} {
		if !have[want] {
			t.Errorf("system:kubelet-api-admin is missing %s (have %v)", want, have)
		}
	}
}

func TestServiceExternalIPsDenied(t *testing.T) {
	_, err := tenant.CoreV1().Services("plain").Create(ctx, svc("mitm", "203.0.113.10"), metav1.CreateOptions{})
	expectDenied(t, err, "externalIPs is not allowed")
	_, err = tenant.CoreV1().Services("plain").Create(ctx, svc("ok"), metav1.CreateOptions{})
	expectAdmitted(t, err)
}

// ---------------------------------------------------------------- network: IMDS

var imds = netip.MustParseAddr("169.254.169.254")
var internet = netip.MustParseAddr("1.1.1.1")

// egressAllows evaluates a single isolating Egress NetworkPolicy for an IP destination.
func egressAllows(np *networkingv1.NetworkPolicy, dst netip.Addr) bool {
	for _, rule := range np.Spec.Egress {
		if len(rule.To) == 0 {
			return true
		}
		for _, peer := range rule.To {
			if peer.IPBlock == nil {
				continue // pod/namespace selectors never match an off-cluster IP
			}
			if !netip.MustParsePrefix(peer.IPBlock.CIDR).Masked().Contains(dst) {
				continue
			}
			excluded := false
			for _, e := range peer.IPBlock.Except {
				if netip.MustParsePrefix(e).Masked().Contains(dst) {
					excluded = true
				}
			}
			if !excluded {
				return true
			}
		}
	}
	return false
}

func loadNetpol(t *testing.T, path string) *networkingv1.NetworkPolicy {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	np := &networkingv1.NetworkPolicy{}
	if err := yaml.Unmarshal(raw, np); err != nil {
		t.Fatal(err)
	}
	return np
}

func TestIMDSNetworkPolicies(t *testing.T) {
	cases := []struct {
		file                   string
		wantIMDS, wantInternet bool
		exceptMatters          bool
		apiRejects             string // "" = admitted
	}{
		{"../policies/netpol-deny-imds.yaml", false, true, true, ""},
		// Microsoft Learn sample: 10.10.0.0/0 means 0.0.0.0/0, but StrictIPCIDRValidation
		// (beta, on by default in 1.36) rejects non-canonical prefixes.
		{"testdata/netpol-imds-docs.yaml", false, true, true, "must not have bits set beyond the prefix length"},
		// /16 variant: the except is a no-op and the API server has always rejected it.
		{"testdata/netpol-imds-slash16.yaml", false, false, false, "must be a strict subset"},
	}
	for _, c := range cases {
		t.Run(filepath.Base(c.file), func(t *testing.T) {
			np := loadNetpol(t, c.file)
			if got := egressAllows(np, imds); got != c.wantIMDS {
				t.Errorf("IMDS allowed = %v, want %v", got, c.wantIMDS)
			}
			if got := egressAllows(np, internet); got != c.wantInternet {
				t.Errorf("internet allowed = %v, want %v", got, c.wantInternet)
			}
			noExcept := np.DeepCopy()
			for i := range noExcept.Spec.Egress {
				for j := range noExcept.Spec.Egress[i].To {
					if b := noExcept.Spec.Egress[i].To[j].IPBlock; b != nil {
						b.Except = nil
					}
				}
			}
			if matters := egressAllows(noExcept, imds) != egressAllows(np, imds); matters != c.exceptMatters {
				t.Errorf("except clause changes the IMDS verdict = %v, want %v", matters, c.exceptMatters)
			}

			np.Namespace = "plain"
			_, err := tenant.NetworkingV1().NetworkPolicies("plain").Create(ctx, np, metav1.CreateOptions{})
			t.Logf("FINDING apiserver: err=%v", err)
			if c.apiRejects == "" {
				expectAdmitted(t, err)
			} else {
				expectDenied(t, err, c.apiRejects)
			}
		})
	}
}
