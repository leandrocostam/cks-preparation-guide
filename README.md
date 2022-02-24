![Check Kubernetes documentation links](https://github.com/leandrocostam/cks-preparation-guide/workflows/Check%20Kubernetes%20documentation%20links/badge.svg)

# Certified Kubernetes Security Specialist (CKS) - V1.23

The objective of this repository is help you for taking the Certified Kubernetes Security Specialist (CKS) exam using online resources, especially using resources from [Kubernetes Official Documentation](https://kubernetes.io).

The references were selected for the [Exam Curriculum 1.23](https://github.com/cncf/curriculum/blob/433eda69a096d599675afa3b00ac6507fc4b893c/CKS_Curriculum_%20v1.23.pdf), and there are exclusive information for API objects and annotations. For more information, please see [CNCF Curriculum](https://github.com/cncf/curriculum/).

Please, feel free to place a pull request whether something is not up-to-date, should be added or contains wrong information/reference.

## CNCF Preparation Guides

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

- Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)

- Properly set up Ingress objects with security control

- Protect node metadata and endpoints

- Minimize use of, and access to, GUI elements

- Verify platform binaries before deploying

## Cluster Hardening (15%)

- Restrict access to Kubernetes API

- Use Role Based Access Controls to minimize exposure

- Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones

- Update Kubernetes frequently

## System Hardening (15%)

- Minimize host OS footprint (reduce attack surface)

- Minimize IAM roles

- Minimize external access to the network

- Appropriately use kernel hardening tools such as AppArmor, seccomp

## Minimize Microservice Vulnerabilities (20%)

- Setup appropriate OS level security domains e.g. using PSP, OPA, security contexts

- Manage kubernetes secrets

- Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers

- Implement pod to pod encryption by use of mTLS

## Supply Chain Security (20%)

- Minimize base image footprint

- Secure your supply chain: whitelist allowed image registries, sign and validate images

- Use static analysis of user workloads (e.g. kubernetes resources, docker files)

- Scan images for known vulnerabilities

## Monitoring, Logging and Runtime Security (20%)

- Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities

- Detect threats within physical infrastructure, apps, networks, data, users and workloads

- Detect all phases of attack regardless where it occurs and how it spreads

- Perform deep analytical investigation and identification of bad actors within environment

- Ensure immutability of containers at runtime

- Use Audit Logs to monitor access

# CKS Preparation Courses

- [Certified Kubernetes Security Specialist (CKS) - A Cloud Guru (formerly Linux Academy)](https://acloudguru.com/course/certified-kubernetes-security-specialist-cks)
- [Udemy - Kubernetes CKS by Kim Wüstkamp)](https://www.udemy.com/course/certified-kubernetes-security-specialist/)

# kubectl Ninja

Tip: Use [kubectl Cheatsheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/) during the exam. You don't need to decorate everything.

# Practice

Practice a lot with Kubernetes:

- [Killer.sh - CKS Simulator](https://killer.sh/cks)
- [Katacoda: CKS Challenges](https://www.katacoda.com/walidshaari/courses/cks-challenges)

# CKS Tips

Some links that contain tips that might help you from different perspectives of the CKS exam.

- [CKS Exam Guide and Tips](https://devopscube.com/cks-exam-guide-tips/)
- [How to pass CKS — Kubernetes Security Specialist exam](https://arekborucki.medium.com/how-to-pass-cks-certified-kubernetes-security-exam-part-1-347e0c48dd32)
