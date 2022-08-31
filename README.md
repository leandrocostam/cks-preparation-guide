![Check Kubernetes documentation links](https://github.com/leandrocostam/cks-preparation-guide/workflows/Check%20Kubernetes%20documentation%20links/badge.svg)

# Certified Kubernetes Security Specialist (CKS) - V1.24

The objective of this repository is help you for taking the Certified Kubernetes Security Specialist (CKS) exam using online resources, especially using resources from [Kubernetes Official Documentation](https://kubernetes.io).

The references were selected for the [Exam Curriculum 1.24](https://github.com/cncf/curriculum/raw/44b3e8aca0556baf934a20017beb5918f05a73df/CKS_Curriculum_%20v1.24.pdf), and there are exclusive information for API objects and annotations. For more information, please see [CNCF Curriculum](https://github.com/cncf/curriculum/).

Please, feel free to place a pull request whether something is not up-to-date, should be added or contains wrong information/reference.

There are other Kubernetes certification exam preparation guides available:

- [Certified Kubernetes Administrator (CKA) - Preparation Guide](https://github.com/leandrocostam/cka-preparation-guide)

# Exam

The exam is kind of "put your hands on", where you have some problems to fix within 120 minutes.

My tip: Spend your time wisely. Use the Notebook feature (provided in exam's UI) to keep track of your progress, where you might take notes of each question, put some annotations in order to help you. Additionally, don't get stuck, move to the next problem, and take it back when you finish all the other problems.

Exam Cost: $375 and includes one free retake.

It's important to mention that you have access to [Kubernetes Official Documentation](https://kubernetes.io) during the exam. So get yourself familiar with Kubernetes online documentation, and know where to find all specific topics listed below. It might be helpful for you during the exam.

For information about the exam, please refer [Certified Kubernetes Security Specialist (CKS) Program](https://www.cncf.io/certification/cks/).

# CKS Curriculum

Exam objectives that outline of the knowledge, skills and abilities that a Certified Kubernetes Security Specialist (CKS) can be expected to demonstrate.

## Cluster Setup (10%)

- Use Network security policies to restrict cluster level access

    - [Kubernetes Documentation > Concepts > Services, Load Balancing, and Networking > Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

- Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)

    - [CIS Security > Securing Kubernetes](https://www.cisecurity.org/benchmark/kubernetes)
    - [Cloud Native Wiki - CIS Benchmark Best Practices](https://www.aquasec.com/cloud-native-academy/kubernetes-in-production/kubernetes-cis-benchmark-best-practices-in-brief/)
    - [GitHub > Aqua Security > kube-bench](https://github.com/aquasecurity/kube-bench)

- Properly set up Ingress objects with security control

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

- Minimize use of, and access to, GUI elements

    - [Kubernetes Documentation > Tasks > Access Applications in a Cluster > Deploy and Access the Kubernetes Dashboard](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/#accessing-the-dashboard-ui)

- Verify platform binaries before deploying

    - [Kubernetes Documentation > Tasks > Install Tools > Install and Set Up kubectl on Linux](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)

        > Note: Check the step 2 - validate binary

## Cluster Hardening (15%)

- Restrict access to Kubernetes API

    - [Kubernetes Documentation > Concepts > Security > Controlling Access to the Kubernetes API](https://kubernetes.io/docs/concepts/security/controlling-access/)

- Use Role Based Access Controls to minimize exposure

    - [Kubernetes Documentation > Reference > API Access Control > Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

- Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones

    - [Kubernetes Documentation > Reference > API Access Control > Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)

- Update Kubernetes frequently

    - [Kubernetes Documentation > Tasks > Administer a Cluster > Upgrade A Cluster](https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade/)

## System Hardening (15%)

- Minimize host OS footprint (reduce attack surface)

    - Remove unnecessary packages
    - Identify and address open ports
    - Shut down any unnecessary services

- Minimize IAM roles

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

- Setup appropriate OS level security domains e.g. using PSP, OPA, security contexts

    - [Kubernetes Documentation > Concepts > Security > Pod Security Policies](https://kubernetes.io/docs/concepts/security/pod-security-policy/#what-is-a-pod-security-policy)
    - [Kubernetes Blog > OPA Gatekeeper: Policy and Governance for Kubernetes](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/)
    - [Kubernetes Documentation > Tasks > Configure Pods and > Containers > Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

- Manage kubernetes secrets

    - [Kubernetes Documentation > Concepts > Configuration > Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)

- Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers

    - [Kubernetes Documentation > Concepts > Security > Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/#what-about-sandboxed-pods)
    - [Kubernetes Documentation > Concepts > Containers > Runtime Class](https://kubernetes.io/docs/concepts/containers/runtime-class/)
    - [gvisor](https://gvisor.dev/docs/user_guide/quick_start/kubernetes/)
    - [kata containers](https://katacontainers.io/)

- Implement pod to pod encryption by use of mTLS

    - [Kubernetes Documentation > Concepts > Services, Load Balancing, and Networking > Ingress > TLS](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)

## Supply Chain Security (20%)

- Minimize base image footprint

    - Remove exploitable and non-sssential software
    - Use multi-stage Dockerfiles to keep software compilation out of runtime images
    - Never bake any secrets into your images
    - Image scanning

- Secure your supply chain: whitelist allowed image registries, sign and validate images

    - [Kubernetes Documentation > Reference > API Access Control > Using Admission Controllers > ImagePolicyWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)

- Use static analysis of user workloads (e.g. kubernetes resources, docker files)

    - Secure base images
    - Remove unnecessary packages
    - Stop containers from using elevated privileges

- Scan images for known vulnerabilities

    - [Trivy](https://github.com/aquasecurity/trivy)

## Monitoring, Logging and Runtime Security (20%)

- Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities

    - [Falco](https://falco.org/docs/)

- Detect threats within physical infrastructure, apps, networks, data, users and workloads

- Detect all phases of attack regardless where it occurs and how it spreads

    - [Protecting Kubernetes Against MITRE ATT&CK](https://cloud.redhat.com/blog/protecting-kubernetes-against-mitre-attck-initial-access)

- Perform deep analytical investigation and identification of bad actors within environment

    - [Kubernetes Documentation > Tasks > Monitoring, Logging, and Debugging >Auditing](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)

- Ensure immutability of containers at runtime

    - [Kubernetes Documentation > Concepts > Containers](https://kubernetes.io/docs/concepts/containers/)
    - [Kubernetes Documentation > Tasks > Configure Pods and > Containers > Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

        > `readOnlyRootFilesystem`: Mounts the container's root filesystem as read-only

- Use Audit Logs to monitor access

    - [Kubernetes Documentation > Tasks > Monitoring, Logging, and Debugging >Auditing](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)

# CKS Preparation Courses

- [Certified Kubernetes Security Specialist (CKS) - A Cloud Guru (formerly Linux Academy)](https://acloudguru.com/course/certified-kubernetes-security-specialist-cks)
- [KodeKloud - Certified Kubernetes Security Specialist (CKS)](https://kodekloud.com/courses/certified-kubernetes-security-specialist-cks/)

# kubectl Ninja

Tip: Use [kubectl Cheatsheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/) during the exam. You don't need to decorate everything.

# Practice

Practice a lot with Kubernetes:

- [Killer.sh - CKS Simulator](https://killer.sh/cks)

# CKS Tips

Some links that contain tips that might help you from different perspectives of the CKS exam.

- [CKS Exam Guide and Tips](https://devopscube.com/cks-exam-guide-tips/)
- [How to pass CKS — Kubernetes Security Specialist exam](https://arekborucki.medium.com/how-to-pass-cks-certified-kubernetes-security-exam-part-1-347e0c48dd32)
