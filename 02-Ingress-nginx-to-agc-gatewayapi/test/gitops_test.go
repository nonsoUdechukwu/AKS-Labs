// Offline tests for the ingress-nginx -> AGC migration GitOps tree.
//
// envtest starts a real kube-apiserver + etcd locally. The test renders each Flux
// Kustomization path with `kubectl kustomize`, performs the same ${VAR}
// substitution Flux does with the values Terraform injects, creates every object
// (so CRD schemas and CEL rules from Gateway API, AGC, cert-manager and Flux are
// enforced), and then checks the migration ratchet and AGC-specific constraints
// that the API server cannot see.
package agctest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

// What Terraform passes through azurerm_kubernetes_flux_configuration post_build.substitute.
var substitutions = map[string]string{
	"ALB_ID":                  "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-plat-test-ingress/providers/Microsoft.ServiceNetworking/trafficControllers/agc-plat-test",
	"ALB_FRONTEND":            "fe-public",
	"ALB_CLIENT_ID":           "11111111-1111-1111-1111-111111111111",
	"WAF_POLICY_ID":           "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-plat-test-ingress/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/wafp-plat-test-agc",
	"CERT_MANAGER_CLIENT_ID":  "22222222-2222-2222-2222-222222222222",
	"DNS_ZONE":                "contoso.example",
	"DNS_ZONE_RESOURCE_GROUP": "rg-plat-test-ingress",
	"AZURE_SUBSCRIPTION_ID":   "00000000-0000-0000-0000-000000000000",
	"ACME_EMAIL":              "platform@contoso.example",
}

// Flux Kustomizations in dependsOn order (mirrors terraform/main.tf).
var kustomizations = []string{
	"../gitops/infrastructure/controllers",
	"../gitops/infrastructure/configs",
	"../gitops/apps",
}

var (
	ctx      = context.Background()
	k8s      client.Client
	cs       *kubernetes.Clientset
	rendered = map[string][]*unstructured.Unstructured{}
	varRef   = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)
)

func TestMain(m *testing.M) {
	env := &envtest.Environment{
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths: []string{
				".crds-cache/gateway-api.yaml",
				".crds-cache/cert-manager.yaml",
				".crds-cache/flux.yaml",
				".crds-cache/alb",
			},
			ErrorIfPathMissing: true,
		},
	}
	cfg, err := env.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest start:", err, "\n(run via ./run.sh)")
		os.Exit(1)
	}
	code := func() int {
		if k8s, err = client.New(cfg, client.Options{}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		cs = kubernetes.NewForConfigOrDie(cfg)
		// Created by the microsoft.flux extension on AKS.
		if err := k8s.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "cluster-config"}}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, dir := range kustomizations {
			objs, err := render(dir)
			if err != nil {
				fmt.Fprintln(os.Stderr, "render", dir, err)
				return 1
			}
			rendered[dir] = objs
			for _, o := range objs {
				if err := k8s.Create(ctx, o.DeepCopy()); err != nil {
					fmt.Fprintf(os.Stderr, "apply %s %s/%s from %s: %v\n", o.GetKind(), o.GetNamespace(), o.GetName(), dir, err)
					return 1
				}
			}
			fmt.Printf("applied %d objects from %s\n", len(objs), dir)
		}
		return m.Run()
	}()
	_ = env.Stop()
	os.Exit(code)
}

func render(dir string) ([]*unstructured.Unstructured, error) {
	out, err := exec.Command("kubectl", "kustomize", dir).Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl kustomize: %w", err)
	}
	var missing []string
	text := varRef.ReplaceAllStringFunc(string(out), func(m string) string {
		k := varRef.FindStringSubmatch(m)[1]
		v, ok := substitutions[k]
		if !ok {
			missing = append(missing, k)
		}
		return v
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("variables not provided by Terraform: %v", missing)
	}
	return decode(text)
}

func decode(text string) ([]*unstructured.Unstructured, error) {
	var objs []*unstructured.Unstructured
	for _, doc := range regexp.MustCompile(`(?m)^---\s*$`).Split(text, -1) {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		m := map[string]any{}
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			return nil, err
		}
		if len(m) == 0 {
			continue
		}
		objs = append(objs, &unstructured.Unstructured{Object: m})
	}
	return objs, nil
}

func allRendered() []*unstructured.Unstructured {
	var all []*unstructured.Unstructured
	for _, d := range kustomizations {
		all = append(all, rendered[d]...)
	}
	return all
}

// ---------------------------------------------------------------------------
// 1. Terraform <-> Git contract
// ---------------------------------------------------------------------------

func TestTerraformGitContract(t *testing.T) {
	src, err := os.ReadFile("../terraform/main.tf")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)flux_substitutions = \{(.*?)\n  \}`).FindSubmatch(src)
	if block == nil {
		t.Fatal("flux_substitutions block not found in main.tf")
	}
	tfKeys := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*([A-Z_]+)\s*=`).FindAllSubmatch(block[1], -1) {
		tfKeys[string(m[1])] = true
	}
	for k := range substitutions {
		if !tfKeys[k] {
			t.Errorf("test substitutes %s but Terraform does not provide it", k)
		}
	}
	used := map[string]bool{}
	_ = filepath.WalkDir("../gitops", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, m := range varRef.FindAllSubmatch(b, -1) {
			used[string(m[1])] = true
			if !tfKeys[string(m[1])] {
				t.Errorf("%s uses ${%s} which Terraform never sets (Flux would substitute an empty string)", p, m[1])
			}
		}
		return nil
	})
	var unused []string
	for k := range tfKeys {
		if !used[k] {
			unused = append(unused, k)
		}
	}
	sort.Strings(unused)
	t.Logf("Terraform keys not referenced in Git (informational): %v", unused)
}

// ---------------------------------------------------------------------------
// 2. Migration ratchet (ValidatingAdmissionPolicy)
// ---------------------------------------------------------------------------

func ingress(ns, name, class string, viaAnnotation bool) *networkingv1.Ingress {
	pt := networkingv1.PathTypePrefix
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: "x.contoso.example",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: &pt, Backend: networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Number: 80}},
				}}},
			}},
		}}},
	}
	if viaAnnotation {
		ing.Annotations = map[string]string{"kubernetes.io/ingress.class": class}
	} else {
		ing.Spec.IngressClassName = &class
	}
	return ing
}

func createIngress(ing *networkingv1.Ingress, dryRun bool) error {
	opts := metav1.CreateOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	_, err := cs.NetworkingV1().Ingresses(ing.Namespace).Create(ctx, ing, opts)
	return err
}

// VAP bindings take a moment to be picked up by the apiserver's policy informer.
func waitForRatchet(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if err := createIngress(ingress("shop", "probe", "nginx", false), true); err != nil && apierrors.IsForbidden(err) && strings.Contains(err.Error(), "is frozen") {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("ratchet policy never became active")
}

func TestRatchet(t *testing.T) {
	waitForRatchet(t)

	deny := []struct {
		name string
		ing  *networkingv1.Ingress
	}{
		{"spec class nginx", ingress("shop", "a", "nginx", false)},
		{"spec class AKS app routing", ingress("shop", "b", "webapprouting.kubernetes.azure.com", false)},
		{"legacy annotation class", ingress("shop", "c", "nginx", true)},
	}
	for _, c := range deny {
		t.Run("deny/"+c.name, func(t *testing.T) {
			err := createIngress(c.ing, true)
			if err == nil || !strings.Contains(err.Error(), "is frozen") {
				t.Fatalf("expected ratchet denial, got %v", err)
			}
		})
	}

	t.Run("allow/ingress on AGC class", func(t *testing.T) {
		if err := createIngress(ingress("shop", "d", "azure-alb-external", false), true); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("deny/every Ingress in legacy/ingress-nginx.yaml", func(t *testing.T) {
		b, err := os.ReadFile("../legacy/ingress-nginx.yaml")
		if err != nil {
			t.Fatal(err)
		}
		objs, err := decode(string(b))
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range objs {
			var ing networkingv1.Ingress
			raw, _ := yaml.Marshal(o.Object)
			if err := yaml.Unmarshal(raw, &ing); err != nil {
				t.Fatal(err)
			}
			if err := createIngress(&ing, true); err == nil || !strings.Contains(err.Error(), "is frozen") {
				t.Errorf("%s: expected denial, got %v", ing.Name, err)
			}
		}
	})

	t.Run("allow/existing legacy Ingress can still be updated", func(t *testing.T) {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "legacy-app",
			Labels: map[string]string{"platform.contoso.io/ingress-exempt": "true"}}}
		if err := k8s.Create(ctx, ns); err != nil {
			t.Fatal(err)
		}
		if err := createIngress(ingress("legacy-app", "web", "nginx", false), false); err != nil {
			t.Fatalf("exempt namespace should allow create: %v", err)
		}
		// Exemption removed: from now on this namespace is ratcheted.
		delete(ns.Labels, "platform.contoso.io/ingress-exempt")
		if err := k8s.Update(ctx, ns); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(15 * time.Second)
		for {
			err := createIngress(ingress("legacy-app", "web2", "nginx", false), true)
			if err != nil && strings.Contains(err.Error(), "is frozen") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("new Ingress should be denied once exemption is removed, got %v", err)
			}
			time.Sleep(250 * time.Millisecond)
		}
		ing, err := cs.NetworkingV1().Ingresses("legacy-app").Get(ctx, "web", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		ing.Annotations = map[string]string{"nginx.ingress.kubernetes.io/proxy-body-size": "8m"}
		if _, err := cs.NetworkingV1().Ingresses("legacy-app").Update(ctx, ing, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("UPDATE of an existing nginx Ingress must stay allowed: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// 3. AGC conformance lint: things the API server accepts but AGC will not program.
// ---------------------------------------------------------------------------

const albController = "azure-alb-external"

func str(o *unstructured.Unstructured, f ...string) string {
	s, _, _ := unstructured.NestedString(o.Object, f...)
	return s
}

func slice(m any, f ...string) []any {
	mm, ok := m.(map[string]any)
	if !ok {
		return nil
	}
	s, _, _ := unstructured.NestedSlice(mm, f...)
	return s
}

func hostMatches(listener, host string) bool {
	if listener == "" {
		return true
	}
	if strings.HasPrefix(listener, "*.") {
		return strings.HasSuffix(host, listener[1:]) && strings.Count(host, ".") >= strings.Count(listener, ".")
	}
	return listener == host
}

func lintAGC(objs []*unstructured.Unstructured) []string {
	var problems []string
	add := func(o *unstructured.Unstructured, f string, a ...any) {
		problems = append(problems, fmt.Sprintf("%s %s/%s: %s", o.GetKind(), o.GetNamespace(), o.GetName(), fmt.Sprintf(f, a...)))
	}
	byKey := map[string]*unstructured.Unstructured{}
	nsLabels := map[string]map[string]string{}
	for _, o := range objs {
		byKey[o.GetKind()+"/"+o.GetNamespace()+"/"+o.GetName()] = o
		if o.GetKind() == "Namespace" {
			nsLabels[o.GetName()] = o.GetLabels()
		}
	}
	certSecrets := map[string]bool{}
	for _, o := range objs {
		if o.GetKind() == "Certificate" {
			certSecrets[o.GetNamespace()+"/"+str(o, "spec", "secretName")] = true
		}
	}

	for _, o := range objs {
		switch {
		case o.GetKind() == "Gateway":
			if str(o, "spec", "gatewayClassName") != albController {
				add(o, "gatewayClassName %q is not served by the ALB controller", str(o, "spec", "gatewayClassName"))
			}
			if o.GetAnnotations()["alb.networking.azure.io/alb-id"] == "" {
				add(o, "missing alb.networking.azure.io/alb-id (BYO deployment)")
			}
			hasFE := false
			for _, a := range slice(o.Object, "spec", "addresses") {
				if am, _ := a.(map[string]any); am["type"] == "alb.networking.azure.io/alb-frontend" {
					hasFE = true
				}
			}
			if !hasFE {
				add(o, "no alb-frontend address: frontend (and FQDN) would not be pinned")
			}
			for _, l := range slice(o.Object, "spec", "listeners") {
				lm := l.(map[string]any)
				if p := fmt.Sprint(lm["port"]); p != "80" && p != "443" {
					add(o, "listener %v uses port %v: AGC supports 80/443 only", lm["name"], p)
				}
				for _, ref := range slice(lm, "tls", "certificateRefs") {
					rm := ref.(map[string]any)
					if !certSecrets[o.GetNamespace()+"/"+fmt.Sprint(rm["name"])] {
						add(o, "listener %v references Secret %v which no cert-manager Certificate produces", lm["name"], rm["name"])
					}
				}
			}

		case o.GetKind() == "HTTPRoute":
			for _, r := range slice(o.Object, "spec", "rules") {
				for _, m := range slice(r, "matches") {
					if t := fmt.Sprint(m.(map[string]any)["path"].(map[string]any)["type"]); t != "PathPrefix" && t != "Exact" {
						add(o, "path match type %s: AGC supports PathPrefix and Exact only", t)
					}
				}
			}
			hosts, _, _ := unstructured.NestedStringSlice(o.Object, "spec", "hostnames")
			for _, p := range slice(o.Object, "spec", "parentRefs") {
				pm := p.(map[string]any)
				ns := fmt.Sprint(pm["namespace"])
				if pm["namespace"] == nil {
					ns = o.GetNamespace()
				}
				gw := byKey["Gateway/"+ns+"/"+fmt.Sprint(pm["name"])]
				if gw == nil {
					add(o, "parentRef Gateway %s/%v not found", ns, pm["name"])
					continue
				}
				found := false
				for _, l := range slice(gw.Object, "spec", "listeners") {
					lm := l.(map[string]any)
					if pm["sectionName"] != nil && lm["name"] != pm["sectionName"] {
						continue
					}
					found = true
					lh, _ := lm["hostname"].(string)
					for _, h := range hosts {
						if !hostMatches(lh, h) {
							add(o, "hostname %s does not match listener %v hostname %s", h, lm["name"], lh)
						}
					}
					ar, _ := lm["allowedRoutes"].(map[string]any)
					nsSel, _ := ar["namespaces"].(map[string]any)
					switch nsSel["from"] {
					case nil, "Same":
						if ns != o.GetNamespace() {
							add(o, "listener %v only allows routes from its own namespace", lm["name"])
						}
					case "Selector":
						sel, _ := nsSel["selector"].(map[string]any)
						ml, _ := sel["matchLabels"].(map[string]any)
						set := labels.Set{}
						for k, v := range ml {
							set[k] = fmt.Sprint(v)
						}
						if !labels.SelectorFromSet(set).Matches(labels.Set(nsLabels[o.GetNamespace()])) {
							add(o, "namespace %s lacks labels %v required by listener %v", o.GetNamespace(), set, lm["name"])
						}
					}
				}
				if !found {
					add(o, "parentRef sectionName %v not found on Gateway %s/%v", pm["sectionName"], ns, pm["name"])
				}
			}

		case o.GetKind() == "BackendTLSPolicy" && strings.HasPrefix(o.GetAPIVersion(), "gateway.networking.k8s.io/"):
			add(o, "Gateway API BackendTLSPolicy is not implemented by AGC: use alb.networking.azure.io BackendTLSPolicy")

		case strings.HasPrefix(o.GetAPIVersion(), "alb.networking.azure.io/"):
			if o.GetKind() == "RoutePolicy" {
				if _, ok := o.Object["spec"].(map[string]any)["override"]; ok {
					add(o, "RoutePolicy supports 'default' only")
				}
			}
			tr, ok, _ := unstructured.NestedMap(o.Object, "spec", "targetRef")
			if ok {
				ns := o.GetNamespace()
				if v, ok := tr["namespace"].(string); ok && v != "" {
					ns = v
				}
				if byKey[fmt.Sprint(tr["kind"])+"/"+ns+"/"+fmt.Sprint(tr["name"])] == nil {
					add(o, "targetRef %v %s/%v does not exist in Git", tr["kind"], ns, tr["name"])
				}
			}
		}
	}
	sort.Strings(problems)
	return problems
}

func TestAGCConformance(t *testing.T) {
	if p := lintAGC(allRendered()); len(p) > 0 {
		t.Fatalf("GitOps tree violates AGC constraints:\n  %s", strings.Join(p, "\n  "))
	}
}

// ingress2gateway output is a useful draft but not deployable on AGC as-is.
// This pins down *why*, so the article's claims are tested rather than asserted.
func TestIngress2GatewayOutputNeedsRework(t *testing.T) {
	b, err := os.ReadFile("../legacy/ingress2gateway-output.yaml")
	if err != nil {
		t.Fatal(err)
	}
	objs, err := decode(string(b))
	if err != nil {
		t.Fatal(err)
	}
	problems := strings.Join(lintAGC(objs), "\n")
	t.Logf("lint findings on raw ingress2gateway output:\n%s", problems)
	for _, want := range []string{
		`gatewayClassName "nginx" is not served`,
		"missing alb.networking.azure.io/alb-id",
		"path match type RegularExpression",
	} {
		if !strings.Contains(problems, want) {
			t.Errorf("expected lint to report %q", want)
		}
	}
}
