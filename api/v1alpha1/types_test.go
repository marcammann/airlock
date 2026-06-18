package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestAddToSchemeRegistersAirlockTypes(t *testing.T) {
	scheme := runtime.NewScheme()

	require.NoError(t, AddToScheme(scheme))

	obj, err := scheme.New(SchemeGroupVersion.WithKind("AirlockPolicy"))
	require.NoError(t, err)
	assert.IsType(t, &AirlockPolicy{}, obj)

	list, err := scheme.New(SchemeGroupVersion.WithKind("AirlockWorkloadList"))
	require.NoError(t, err)
	assert.IsType(t, &AirlockWorkloadList{}, list)
}

func TestAirlockTypesWorkWithControllerRuntimeClient(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, AddToScheme(scheme))
	policy := &AirlockPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: APIVersion,
			Kind:       "AirlockPolicy",
		},
		Metadata: Metadata{
			Name:      "openai",
			Namespace: "demo",
		},
		Spec: PolicySpec{
			Egress: []EgressRule{{
				Name:   "openai",
				Scheme: "https",
				Host:   "api.openai.com",
			}},
		},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()

	var out AirlockPolicyList
	require.NoError(t, kube.List(context.Background(), &out, client.InNamespace("demo")))

	require.Len(t, out.Items, 1)
	assert.Equal(t, "openai", out.Items[0].Metadata.Name)
	assert.Equal(t, "api.openai.com", out.Items[0].Spec.Egress[0].Host)
}

func TestDeepCopyObjectCopiesMutableFields(t *testing.T) {
	policy := &AirlockPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: APIVersion,
			Kind:       "AirlockPolicy",
		},
		Metadata: Metadata{
			Name:        "openai",
			Namespace:   "demo",
			Annotations: map[string]string{"one": "two"},
		},
		Spec: PolicySpec{
			Egress: []EgressRule{{
				Name:     "openai",
				Scheme:   "https",
				Host:     "api.openai.com",
				Rewrites: []RewriteRule{{Target: "header", Name: "Authorization"}},
			}},
		},
		Status: Status{
			Conditions: []StatusCondition{{Type: "Ready", Status: "True"}},
		},
	}

	copied := policy.DeepCopyObject().(*AirlockPolicy)
	copied.Metadata.Annotations["one"] = "changed"
	copied.Spec.Egress[0].Rewrites[0].Name = "X-Test"
	copied.Status.Conditions[0].Status = "False"

	assert.Equal(t, "two", policy.Metadata.Annotations["one"])
	assert.Equal(t, "Authorization", policy.Spec.Egress[0].Rewrites[0].Name)
	assert.Equal(t, "True", policy.Status.Conditions[0].Status)
}
