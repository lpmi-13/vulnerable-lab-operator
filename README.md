# vulnerable-k8s-operator

Sometimes, it's helpful to practice identifying security vulnerabilities in a running k8s cluster that's not production. So this is a very simple k8s operator that picks a random vulnerability from the [OWASP Kubernetes Top Ten](https://owasp.org/www-project-kubernetes-top-ten/) and configures a k3s cluster with that misconfiguration.

## Owasp categories

[K01: Insecure Workload Configurations](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K01-insecure-workload-configurations)

[K02: Supply Chain Vulnerabilities](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K02-supply-chain-vulnerabilities)

[K03: Overly Permissive RBAC Configurations](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K03-overly-permissive-rbac)

[K04: Lack of Centralized Policy Enforcement](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K04-policy-enforcement) (we're skipping this one, since it's difficult to detect controls that evaluate the results of scans)

[K05: Inadequate Logging and Monitoring](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K05-inadequate-logging) (we're also skipping this one for now, since it's detecting an absence of something outside the cluster)

[K06: Broken Authentication Mechanisms](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K06-broken-authentication)

[K07: Missing Network Segmentation Controls](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K07-network-segmentation)

[K08: Secrets Management Failures](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K08-secrets-management)

[K09: Misconfigured Cluster Components](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K09-misconfigured-cluster-components)
(we're skipping this one because it would require cluster-level and admin)

[K10: Outdated and Vulnerable Kubernetes Components](https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K10-vulnerable-components)
(we're skipping this one for the same reason as K09)

> NB: Becuase K04/K05/K09/K10 are all a bit tricky/brittle to detect, we've skipped them here, but they're all definitely part of a wider security audit that should be done in a production system.

The first thing to do is run some scanners to see what you can pick up (or you can eyeball the cluster/spec/etc, but the scanners are probably what you'll be using in production automation).

- [kubescape](https://kubescape.io/docs/install-cli/) (for K01, K03, K07, K08)
- kubeaudit (for K01, K06, K08) - deprecated, team recommends moving to kube-bench
- [kube-bench](https://aquasecurity.github.io/kube-bench/v0.6.7/installation/) (for K09)
- [kube-score](https://github.com/zegl/kube-score)
- [trivy](https://trivy.dev/dev/getting-started/installation/) (for K02, once you've identified an insecure image...or you can run it in "k8s mode")

### scanning commands

Find the vulnerabilities by running one of the following scans:

- scan the entire namespace with kubescape
```sh
$ kubescape scan --include-namespaces test-lab
```

- scan a specific deployment in the namespace with kubescape
```sh
$ kubescape scan workload Deployment/<deployment-name> --include-namespaces test-lab
```

- scan the entire namespace with trivy
```sh
$ trivy k8s --include-namespaces test-lab --report summary
```

- scan a specific deployment in the namespace with trivy
```sh
$ trivy k8s --include-namespaces test-lab --report summary deployments/<deployment-name>
```

- scan all the deployment yaml manifests with kube-score (this one has to scan file contents, so it's a bit gnarly)
```sh
$ kubectl api-resources --verbs=list --namespaced -o name \
  | xargs -n1 -I{} bash -c "kubectl get {} -n test-lab -oyaml && echo ---" \
  | kube-score score -
```

## Sub-categories

Each vulnerability category has multiple sub-issues that are randomly selected:

- K01 (Insecure Workload Configurations) - 3 sub-issues:

  1. Privileged container - Sets privileged: true
  2. Running as root - Sets runAsUser: 0
  3. Dangerous capabilities - Adds SYS_ADMIN, NET_ADMIN capabilities

- K02 (Supply Chain Vulnerabilities) - 5 sub-issues:

  1. api: node:16-alpine (outdated vs node:22-alpine)
  2. webapp: nginx:1.20-alpine (outdated vs nginx:1.29.1-alpine)
  3. user-service: python:3.9-alpine (outdated vs python:3.13-alpine)
  4. payment-service: ruby:3.0-alpine (outdated vs ruby:3.3-alpine)
  5. grafana: grafana/grafana:9.0.0 (outdated vs grafana/grafana:12.0.0)

- K03 (Overly Permissive RBAC) - 4 sub-issues:

  1. Cluster Admin Access - Grants cluster-admin permissions
  2. Secret Access - Grants broad secret access across cluster
  3. Cross-Namespace Access - Grants access to kube-system namespace
  4. Node Access - Grants access to node resources and metrics

- K06 (Broken Authentication) - 6 sub-issues:

  1. Default service account usage - Removes explicit serviceAccountName
  2. Service account token annotation - Adds token requirement annotation
  3. Default service account annotation - Adds temporary account annotation
  4. Missing fsGroup in PodSecurityContext - Creates PodSecurityContext without fsGroup
  5. Root user with volume access - Sets runAsUser: 0 (detected by Kubescape C-0013)
  6. Privileged container with volume access - Sets privileged: true (detected by Kubescape C-0016)

- K07 (Missing Network Segmentation) - 4 sub-issues:

  1. Unrestricted pod-to-pod communication - Adds network policy disabled annotation
  2. Network isolation disabled - Adds isolation disabled annotation
  3. Database exposure - Changes PostgreSQL service to NodePort
  4. Service exposure annotation - Adds external database access annotation

- K08 (Secrets Management Failures) - 3 sub-issues:

  1. Secret data in ConfigMaps - Stores sensitive data in ConfigMap instead of Secret
  2. Hardcoded secrets annotation - Adds development mode annotation
  3. Insecure volume permissions - Adds debugging enabled annotation



## Description

The operator is geared toward two distinct, though related, use cases.

1. Running it in [Iximiuz Labs](https://labs.iximiuz.com) as a learning resource for users wanting practice finding and remediating kubernetes vulnerabilities like this.

2. Running it in a remote ephemeral namespace for teams to test out their security scanning (I have no idea if anybody actually wants to do this, but I tried to make it as easy as possible)

For the first case, we just clone this repository and run `make manifests`, `make install` and `make run`, which is not at all how you would normally deploy an operator in a production context, but it gives us a few advantages.

- We don't want the operator itself to get flagged by the scans, and this way it doesn't actually run in the cluster, so it won't interfere with the investigation of the learners..
- This is a completely ephemeral environment of a single node k3s cluster, and it's much easier and quicker than needing to deal with a container registry.
- The logs of what the configured vulnerability is are harder for the learner to find, and so less of a temptation to "cheat" (though they could still be found, they're just not findable via a `kubectl logs` command).

## Sequence of events in the labs

The custom playground will download the repo and build the operator. It will start the operator and echo out to the user with the `wall` utility every time the operator resets. The user can continue finding and fixing the vulnerabilities as long as they want.

## Getting Started

Quick-start: if nothing is happening, run these commands, in order:
- kubectl delete vulnerablelab test-lab
- kubectl delete ns test-lab --ignore-not-found
- make manifests (you probably don't need this unless you updated code in the operator)
- make install
- make run
- and then you can create the CRD. If you pass in `vulnerability: "random"` or `spec: {}`, then it selects randomly from the list of categories. If you instead want to specify which vulnerability, you can pass that in directly via `vulnerability: K05`.

> examples of the final step are below, and it's the thing that actually creates the CRD...the reconciler won't do anything until that happens

### Examples of creating a new CRD with varying levels of randomness

complete random selection of sub-issue from within a random category:

```sh
kubectl apply -f - <<EOF
apiVersion: lab.security.lab/v1alpha1
kind: VulnerableLab
metadata:
  name: test-lab
spec:
  vulnerability: "random"
EOF
```

complete random selection of sub-issue from within a specific category:

```sh
kubectl apply -f - <<EOF
apiVersion: lab.security.lab/v1alpha1
kind: VulnerableLab
metadata:
  name: test-lab
spec:
  vulnerability: "K01"
EOF
```

specific selection of a sub-issue from within a specific category:

```sh
kubectl apply -f - <<EOF
apiVersion: lab.security.lab/v1alpha1
kind: VulnerableLab
metadata:
  name: test-lab
spec:
  vulnerability: "K01"
  subIssue: 0
EOF
```


### Prerequisites
- go version v1.24.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/vulnerable-k8s-operator:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
kubectl apply -f <url-to-yaml>
```

> We don't have the yaml for this yet, but once we're ready, I can put it in a github repo

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/vulnerable-k8s-operator:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/vulnerable-k8s-operator:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/vulnerable-k8s-operator/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
operator-sdk edit --plugins=helm/v1-alpha
```

2. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## Testing

This project includes comprehensive unit tests for the core vulnerability logic in the `internal/breaker` package. You can run these tests with:

```sh
go test ./internal/breaker/ -v
```

**Note on Integration Tests**: The original Kubebuilder-generated controller and e2e integration tests have been removed because they require additional Kubernetes infrastructure dependencies (`kubebuilder`, `kind`, `etcd`, etc.). For an educational vulnerability lab operator, the unit tests that validate the core vulnerability application logic are sufficient and more practical. The integration tests mainly verified basic Kubernetes CRUD operations which are already well-tested by the controller-runtime framework.

## Contributing
PRs are always welcome, though I don't imagine anyone will be interested in this project.

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

