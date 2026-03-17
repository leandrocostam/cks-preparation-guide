![Check Kubernetes documentation links](https://github.com/leandrocostam/cks-preparation-guide/workflows/Check%20Kubernetes%20documentation%20links/badge.svg)

# Certified Kubernetes Security Specialist (CKS) - V1.34

The objective of this repository is help you for taking the Certified Kubernetes Security Specialist (CKS) exam using online resources, especially using resources from [Kubernetes Official Documentation](https://kubernetes.io).

The references were selected for the [Exam Curriculum 1.34](https://github.com/cncf/curriculum/blob/94f35b01ae65763117de7fd5fcd5d57feacae68c/CKS_Curriculum%20v1.34.pdf), and there are exclusive information for API objects and annotations. For more information, please see [CNCF Curriculum](https://github.com/cncf/curriculum/).

Please, feel free to place a pull request whether something is not up-to-date, should be added or contains wrong information/reference.

There are other Kubernetes certification exam preparation guides available:

- [Certified Kubernetes Administrator (CKA) - Preparation Guide](https://github.com/leandrocostam/cka-preparation-guide)

# Exam

The exam is kind of "put your hands on", where you have some problems to fix within 120 minutes.

My tip: Spend your time wisely. Use the Notebook feature (provided in exam's UI) to keep track of your progress, where you might take notes of each question, put some annotations in order to help you. Additionally, don't get stuck, move to the next problem, and take it back when you finish all the other problems.

Exam Cost: $445 and includes one free retake.

It's important to mention that you have access to [Kubernetes Official Documentation](https://kubernetes.io) during the exam. So get yourself familiar with Kubernetes online documentation, and know where to find all specific topics listed below. It might be helpful for you during the exam.

For information about the exam, please refer [Certified Kubernetes Security Specialist (CKS) Program](https://www.cncf.io/certification/cks/).

# CKS Curriculum

Exam objectives that outline of the knowledge, skills and abilities that a Certified Kubernetes Security Specialist (CKS) can be expected to demonstrate.

## Cluster Setup (15%)

- Use Network security policies to restrict cluster level access

    - [Kubernetes Documentation > Concepts > Services, Load Balancing, and Networking > Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

- Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)

    - [CIS Security > Securing Kubernetes](https://www.cisecurity.org/benchmark/kubernetes)
    - [GitHub > Aqua Security > kube-bench](https://github.com/aquasecurity/kube-bench)

- Properly set up Ingress objects with TLS

    - [Kubernetes Documentation > Concepts > Services, Load Balancing, and Networking > Ingress > TLS](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)

- Protect node metadata and endpoints

    - [Kubernetes Documentation > Tasks > Administer a Cluster > Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access)

        ```yaml
        # all pods in namespace cannot access metadata endpoint
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
        name: cloud-metadata-deny
        namespace: default
        spec:
        podSelector: {}
        policyTypes:
        - Egress
        egress:
        - to:
            - ipBlock:
                cidr: 0.0.0.0/0
                except:
                - 169.254.169.254/32
        ```
        > NOTE: when using Cilium, the `NetworkPolicy` above will block all egress traffic to _all pods/services in the cluster_ (despite the `0.0.0.0/0`), including kube-dns. A pod targeted by this policy that attempts to connect to `example.com` will fail because the pod will not be able reach kube-dns to do the name resolution but that same pod will be able to reach the IP of `example.com` (e.g. `104.18.26.120`) or any other external IP. This is known behavior with Cilium's interpretation of `ipBlock` policies which applies them _only to IPs that are outside the cluster_: https://docs.cilium.io/en/stable/network/kubernetes/policy/#networkpolicy-state. It is worth understanding this behavior for the exam as Cilium is specifically called out in the curriculum.

- Verify platform binaries before deploying

    - [Release History > Download Kubernetes > Binaries](https://kubernetes.io/releases/download/#binaries)
    - [Kubernetes Documentation > Tasks > Administer a Cluster > Verify Signed Kubernetes Artifacts](https://kubernetes.io/docs/tasks/administer-cluster/verify-signed-artifacts/)

## Cluster Hardening (15%)

- Use Role Based Access Controls to minimize exposure

    - [Kubernetes Documentation > Reference > API Access Control > Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

- Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones

    - [Kubernetes Documentation > Reference > API Access Control > Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)

- Restrict access to Kubernetes API

    - [Kubernetes Documentation > Concepts > Security > Controlling Access to the Kubernetes API](https://kubernetes.io/docs/concepts/security/controlling-access/)

- Update Kubernetes to avoid vulnerabilities

    - [Kubernetes Documentation > Tasks > Administer a Cluster > Upgrade A Cluster](https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade/)

## System Hardening (10%)

- Minimize host OS footprint (reduce attack surface)

    - Remove unnecessary packages
    - Identify and address open ports
    - Shut down any unnecessary services
    - [Kubernetes Documentation > Tasks > Administer a Cluster > Securing a Cluster > Preventing containers from loading unwanted kernel modules](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#preventing-containers-from-loading-unwanted-kernel-modules)

- Using least-privilege identity and access management

    - [Kubernetes Documentation > Concepts > Security > Role Based Access Control Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
    - [AWS > Security best practices in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
    - [GCP - Using IAM securely](https://cloud.google.com/iam/docs/using-iam-securely)
    - [Azure > Best practices for Azure RBAC](https://docs.microsoft.com/en-us/azure/role-based-access-control/best-practices)

- Minimize external access to the network

    - [Kubernetes Documentation > Concepts > Services, Load Balancing, and Networking > Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

- Appropriately use kernel hardening tools such as AppArmor, seccomp

    - [Kubernetes Documentation > Tutorials > Security > Restrict a Container's Access to Resources with AppArmor](https://kubernetes.io/docs/tutorials/security/apparmor/)
    - [Kubernetes Documentation > Tutorials > Security > Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)
    - [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)

## Minimize Microservice Vulnerabilities (20%)

- Use appropriate pod security standards

    - [Kubernetes Documentation > Concepts > Security > Pod Security Standards > Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
    - [Kubernetes Documentation > Tasks > Configure Pods and Containers > Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
    - [Kubernetes Blog > OPA Gatekeeper: Policy and Governance for Kubernetes](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/)

- Manage kubernetes secrets

    - [Kubernetes Documentation > Concepts > Configuration > Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)

- Understand and implement isolation techniques (multi-tenancy, sandboxed containers,
etc.)

    - [Kubernetes Documentation > Concepts > Security > Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/#what-about-sandboxed-pods)
    - [Kubernetes Documentation > Concepts > Containers > Runtime Class](https://kubernetes.io/docs/concepts/containers/runtime-class/)
    - [gvisor](https://gvisor.dev/docs/user_guide/quick_start/kubernetes/)
    - [kata containers](https://katacontainers.io/)

- Implement Pod-to-Pod encryption (Cilium, Istio)

    - [Transparent Encryption](https://docs.cilium.io/en/stable/security/network/encryption/)
    - [Kubernetes Documentation > Concepts > Services, Load Balancing, and Networking > Ingress > TLS](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)
    - [Istio Documentation > Reference > Configuration > Security > Authorization Policy](https://istio.io/latest/docs/reference/config/security/authorization-policy/)

## Supply Chain Security (20%)

- Minimize base image footprint

    - Remove exploitable and non-essential software
      - [Distroless containers](https://github.com/GoogleContainerTools/distroless)
      - [Docker Hardened Images](https://www.docker.com/products/hardened-images/)
      - [SlimToolkit](https://slimtoolkit.org/)
    - [Use multi-stage Dockerfiles to keep software compilation out of runtime images](https://docs.docker.com/develop/develop-images/multistage-build/)
      - Example [Docker multi-stage build with Go](https://youtu.be/wQDkLxj9ALs)
    - Never bake any secrets into your images
      - [Short video example on what not to do](https://youtube.com/shorts/4S5qIklNCRc)
    - Image scanning
      - [Trivy](https://github.com/aquasecurity/trivy)
      - [Clair](https://clairproject.org/)

- Understand your supply chain (e.g. SBOM, CI/CD, artifact repositories)

    - [bom CLI reference > bom validate > Check artifacts against SPDX manifests with bom](https://kubernetes-sigs.github.io/bom/cli-reference/bom_validate/)
    - [GitHub articles > What is a software bill of materials (SBOM)?](https://github.com/resources/articles/what-is-an-sbom-software-bill-of-materials)
    - [Linux Foundation: SPDX tools](https://spdx.dev/use/spdx-tools/)

- Secure your supply chain (permitted registries, sign and validate artifacts, etc.)

    - [Kubernetes Documentation > Reference > API Access Control > Using Admission Controllers > ImagePolicyWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)
    - [Sign and verify container images with Sigstore Cosign](https://docs.sigstore.dev/cosign/)

- Perform static analysis of user workloads and container images (e.g. Kubesec, KubeLinter)

    - Secure base images
    - Remove unnecessary packages
    - Stop containers from using elevated privileges
    - Tools:
      - [Trivy](https://github.com/aquasecurity/trivy)
      - [KubeLinter](https://docs.kubelinter.io/)
      - [Kube-score](https://kube-score.com/)
      - [kubesec](https://kubesec.io/)
      - [Checkov](https://www.checkov.io/)

## Monitoring, Logging and Runtime Security (20%)

- Perform behavioral analytics to detect malicious activities

    - Use syscall process and file activities at the host and container level
      - [Kubernetes Blog > Monitoring Kubernetes with sysdig](https://kubernetes.io/blog/2015/11/monitoring-kubernetes-with-sysdig/)
      - [Falco](https://falco.org/docs/)
      - [Falco Rules](https://falco.org/docs/reference/rules/)

- Detect threats within physical infrastructure, apps, networks, data, users and workloads

    - [Common Kubernetes config security threats](https://www.cncf.io/blog/2020/08/07/common-kubernetes-config-security-threats/)
    - [A Deep Dive Into Kubernetes Threat Modeling](https://www.trendmicro.com/vinfo/us/security/news/security-technology/a-deep-dive-into-kubernetes-threat-modeling)
    - [Threat matrix for Kubernetes](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)

- Investigate and identify phases of attack and bad actors within the environment

    - [Protecting Kubernetes Against MITRE ATT&CK](https://cloud.redhat.com/blog/protecting-kubernetes-against-mitre-attck-initial-access)
    - [Kubernetes Documentation > Tasks > Monitoring, Logging, and Debugging >Auditing](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)

- Ensure immutability of containers at runtime

    - [Kubernetes Documentation > Concepts > Containers](https://kubernetes.io/docs/concepts/containers/)
    - [Kubernetes Documentation > Tasks > Configure Pods and > Containers > Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

        > `readOnlyRootFilesystem`: Mounts the container's root filesystem as read-only

- Use Kubernetes audit logs to monitor access

    - [Kubernetes Documentation > Tasks > Monitoring, Logging, and Debugging >Auditing](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)

# CKS Preparation Courses

- [Free CKS Self-Study Course - RX-M](https://rx-m.com/cks-self-study-course/)
- [Certified Kubernetes Security Specialist (CKS) video course - Pluralsight](https://www.pluralsight.com/courses/certified-kubernetes-security-specialist-cks)
- [Certified Kubernetes Security Specialist (CKS) video course - KodeKloud](https://kodekloud.com/courses/certified-kubernetes-security-specialist-cks/)
- [Certified Kubernetes Security Specialist (CKS) 5-day live, instructor-led Boot Camp - RX-M](https://rx-m.com/training/certified-kubernetes-security-specialist-cks-boot-camp/)
- [Certified Kubernetes Security Specialist (CKS) 1-day live, instructor-led Exam Prep - RX-M](https://rx-m.com/training/certified-kubernetes-security-specialist-cks-exam-prep/)

# kubectl Ninja

Tip: Use [kubectl Cheatsheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/) during the exam. You don't need to decorate everything.

# Practice

Practice a lot with Kubernetes:

- [Killer.sh - CKS Simulator](https://killer.sh/cks)
- [KillerCoda - CKS Simulator](https://killercoda.com/killer-shell-cks)

# CKS Tips

Some links that contain tips that might help you from different perspectives of the CKS exam.

- [CKS Exam Guide and Tips](https://devopscube.com/cks-exam-guide-tips/)
- [How to pass CKS — Kubernetes Security Specialist exam](https://arekborucki.medium.com/how-to-pass-cks-certified-kubernetes-security-exam-part-1-347e0c48dd32)
- [Everything you need to know about Kubernetes certification CNCF webinar](https://youtu.be/vFvelHoxeP0)
