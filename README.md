# Terraform 으로 EKS를 구축하여 Helm으로 Horizontal Pod Autoscaler(HPA), Cluster Autoscaler(CA), ALB Ingress 적용
## 요약
k8s에서 오토 스케일 Web 애플리케이션을 실행하면 Deployment 및 Service 외에도 Ingress, Horizontal Pod Autoscaler (HPA)까지 만들 수 있습니다.
또한 호스트의 오토 스케일링을 위해서는 Cluster Autoscaler (CA)의 도입도 필요합니다.

그래서 Amazon EKS Workshop 등을 참고로 EKS에서 HPA, CA, Ingress까지 시도 순조롭게 진행되지 않고 빠진 점을 포함 해 정리했습니다.

이 글의 소스 코드는 [여기](https://github.com/os1ma/eks-sample/tree/master/terraform-eks-helming-hpa-ca-alb-ingress) 입니다.

## 준비
다음 도구가 설치된 Mac에서 

* kubectl v1.13.1
* aws cli 1.16.70
* ~ / .aws / credentials도 구성된합니다
* aws-iam-authenticator heptio-authenticator-aws에서 이름이 바뀌어 있기 때문에주의하십시오
* helm v2.12.1
* terraform v0.11.10
* jq 1.6

## 테스트 단계
1. Terraform에서 EKS를 구축
2. Helm 설치
3. Metrics Server를 설치
4. Cluster Autoscaler 설치
5. AWS ALB Ingress Controller를 설치
6. Deployment, Service, Ingress, HPA를 작성
7. 스케일링 테스트

## 내용
### Terraform으로 EKS 구축
최근에는 eksctl에서 구축하는 샘플이 많지만 Terraform으로 구축하고 싶었 때문에 terraform-aws-modules/eks를 사용했습니다.
특히 eks_test_fixture example을 참조하여 다음 세 파일을 만들었습니다.

- providers.tf
```

provider "aws" {
  version = ">= 1.24.0"
  region  = "ap-northeast-1"
}

provider "random" {
  version = "= 1.3.1"
}

```
- vpc.tf
```

data "aws_availability_zones" "available" {}

resource "aws_security_group" "all_worker_mgmt" {
  name_prefix = "all_worker_management"
  vpc_id      = "${module.vpc.vpc_id}"

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"

    cidr_blocks = [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
    ]
  }
}

module "vpc" {
  source             = "terraform-aws-modules/vpc/aws"
  version            = "1.14.0"
  name               = "test-vpc"
  cidr               = "10.0.0.0/16"
  azs                = ["${data.aws_availability_zones.available.names[0]}", "${data.aws_availability_zones.available.names[1]}", "${data.aws_availability_zones.available.names[2]}"]
  private_subnets    = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets     = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
  enable_nat_gateway = true
  single_nat_gateway = true
  tags               = "${merge(local.tags, map("kubernetes.io/cluster/${local.cluster_name}", "shared"))}"
}

```

- eks.tf
```

locals {
  cluster_name = "test-eks-${random_string.suffix.result}"
  worker_groups = [
    {
      instance_type       = "t2.small"
      subnets             = "${join(",", module.vpc.private_subnets)}"
    },
  ]
  tags = {
    Environment = "test"
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
}

module "eks" {
  source                               = "terraform-aws-modules/eks/aws"
  cluster_name                         = "${local.cluster_name}"
  subnets                              = ["${module.vpc.private_subnets}"]
  tags                                 = "${local.tags}"
  vpc_id                               = "${module.vpc.vpc_id}"
  worker_groups                        = "${local.worker_groups}"
  worker_group_count                   = "1"
  worker_additional_security_group_ids = ["${aws_security_group.all_worker_mgmt.id}"]
}

```

파일을 만든 후 Terraform을 실행합니다.
```
$ ls
eks.tf       providers.tf vpc.tf
$ terraform init
$ terraform apply
```

이것만으로 EKS와 worke nodes가 생성됩니다.

Terraform의 실행이 완료되면 worke nodes를 등록하기위한 ConfigMap과 kubeconfig 확인 할 수 있습니다.
```
$ ls
config-map-aws-auth_test-eks-pSfTUN5w.yaml providers.tf
eks.tf                                     terraform.tfstate
kubeconfig_test-eks-pSfTUN5w               vpc.tf
```

Configmap은 적용 되었기 때문에 kubectl apply 할 필요가 없습니다.
kubeconfig는 환경 변수로 설정합니다.

```
$ export KUBECONFIG=`pwd`/`ls kubeconfig_*`
$ kubectl get configmaps --all-namespaces
NAMESPACE     NAME                                 DATA   AGE
kube-system   aws-auth                             3      3m
kube-system   coredns                              1      4m
kube-system   extension-apiserver-authentication   5      4m
kube-system   kube-proxy                           1      4m
$ kubectl get nodes
NAME                                            STATUS   ROLES    AGE   VERSION
ip-10-0-1-211.ap-northeast-1.compute.internal   Ready    <none>   2m    v1.11.5
```

### Helm 설치
Install Helm CLI용 Helm을 설치합니다.

- helm/rbac.yaml
```
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tiller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: tiller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: tiller
    namespace: kube-system
```

```
$ kubectl apply -f helm/rbac.yaml
$ helm init --service-account tiller --upgrade
```

tiller의 Pod가 시작되면 Helm 설치가 완료됩니다.
```
$ kubectl get po --all-namespaces
NAMESPACE     NAME                             READY   STATUS    RESTARTS   AGE
kube-system   aws-node-dkzxr                   1/1     Running   1          6m
kube-system   coredns-7774b7957b-fndtt         1/1     Running   0          8m
kube-system   coredns-7774b7957b-nmc6q         1/1     Running   0          8m
kube-system   kube-proxy-bvzwf                 1/1     Running   0          6m
kube-system   tiller-deploy-85744d9bfb-ghm5j   1/1     Running   0          22s
```

### Metrics Server
#### 설치

HPA는 Metrics Server에 의존하고 있기 때문에 [Configure Horizontal Pod Autoscaler(HPA)](https://eksworkshop.com/scaling/deploy_hpa/)를 참고하여 Helm에서 Metrics Server를 설치합니다.

CI를 위해 helm install 대신 helm upgrade --install을 사용하고 있습니다.

```
$ helm upgrade --install \
    metrics-server \
    stable/metrics-server \
    --version 2.0.4 \
    --namespace kube-system
```

#### VPC DNS설정
Metrics Server가 무사히 설치 했다면 kubectl top nodes 등으로 메트릭을 확인할 수 있습니다.
그러나 이 시점의 설정은 기다려도 통계 수집을 할 수 없습니다.

```
$ kubectl top nodes
error: metrics not available yet
```

Metrics Server의 로그를 확인하면 ...
```
$ kubectl -n kube-system logs metrics-server-5f64dbfb9d-rc67t
    :
E1231 02:40:13.761695       1 manager.go:102] unable to fully collect metrics: unable to fully scrape metrics from source kubelet_summary:ip-10-0-1-211.ap-northeast-1.compute.internal: unable to fetch metrics from Kubelet ip-10-0-1-211.ap-northeast-1.compute.internal (ip-10-0-1-211.ap-northeast-1.compute.internal): Get https://ip-10-0-1-211.ap-northeast-1.compute.internal:10250/stats/summary/: dial tcp: lookup ip-10-0-1-211.ap-northeast-1.compute.internal on 172.20.0.10:53: no such host
    :

```

worker nodes의 이름 확인하지 못한 것이 원인 인 것 같습니다.
이는 AWS VPC Terraform Module은 기본적으로 enable_dns_hostnames이 false로 설정되어 있기 때문입니다.

vpc.tf에 enable_dns_hostnames = true라는 설명을 추가하여 다시 Terraform을 실행합니다.
```
$ cat vpc.tf
    :
module "vpc" {
    :
  enable_dns_hostnames = true
    :
}
$ terraform apply
```
잠시 기다리면 통계가 수집되는 것을 확인 할 수 있습니다.

```
$ kubectl top nodes
NAME                                            CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
ip-10-0-1-211.ap-northeast-1.compute.internal   30m          3%     330Mi           17%
```
HPA 동작은 CA와 함께 확인 할 것입니다.

#### 참고
[VP DNS 사용](https://docs.aws.amazon.com/ja_jp/vpc/latest/userguide/vpc-dns.html)
[terraform-aws-modules/terraform-aws-vpc - variables.tf](https://github.com/terraform-aws-modules/terraform-aws-vpc/blob/master/variables.tf)

### Cluster Autoscaler
#### 설치
[terraform-aws-eks - autoscaling.md](https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/docs/autoscaling.md)를 참고하여 Cluster Autoscaler를 설치합니다.

values.yaml을 만들지 만, 지역 및 클러스터 이름은 여기에서 설명하지 않고 Helm 런타임 인수로 전달할 수 있습니다

- cluster-autoscaler/values.yaml
```
rbac:
  create: true

sslCertPath: /etc/ssl/certs/ca-bundle.crt

cloudProvider: aws

autoDiscovery:
  enabled: true
```

helm upgrade --install 를 실행 합니다.
```
$ helm upgrade --install \
    cluster-autoscaler \
    stable/cluster-autoscaler \
    --version 0.11.0 \
    --namespace kube-system \
    --values cluster-autoscaler/values.yaml \
    --set autoDiscovery.clusterName=test-eks-pSfTUN5w \
    --set awsRegion=ap-northeast-1
```

CA의 상태는 ConfigMap의 cluster-autoscaler-status에서 확인할 수 있습니다.
이 시점에서 CA는 설치되었지만 아직 조정 대상 작업자 그룹이 등록되어 있지 않습니다.
```
$ kubectl -n kube-system describe configmaps cluster-autoscaler-status
Name:         cluster-autoscaler-status
Namespace:    kube-system
Labels:       <none>
Annotations:  cluster-autoscaler.kubernetes.io/last-updated: 2018-12-31 03:20:54.995043016 +0000 UTC

Data
====
status:
----
Cluster-autoscaler status at 2018-12-31 03:20:54.995043016 +0000 UTC:
Cluster-wide:
  Health:      Healthy (ready=1 unready=0 notStarted=0 longNotStarted=0 registered=1 longUnregistered=0)
               LastProbeTime:      2018-12-31 03:20:54.932736374 +0000 UTC m=+222.490186161
               LastTransitionTime: 2018-12-31 03:17:22.931577808 +0000 UTC m=+10.489027591
  ScaleUp:     NoActivity (ready=1 registered=1)
               LastProbeTime:      2018-12-31 03:20:54.932736374 +0000 UTC m=+222.490186161
               LastTransitionTime: 2018-12-31 03:17:22.931577808 +0000 UTC m=+10.489027591
  ScaleDown:   NoCandidates (candidates=0)
               LastProbeTime:      2018-12-31 03:20:54.932736374 +0000 UTC m=+222.490186161
               LastTransitionTime: 2018-12-31 03:17:22.931577808 +0000 UTC m=+10.489027591

Events:  <none>
```

#### worker group 등록
스케일링 대상 작업자 그룹을 등록하기 위해 eks.tf을 수정하여 작업자 그룹의 설정을 변경합니다.
autoscaling_enabled = true와 protect_from_scale_in = true를 추기하고 asg_min_size, asg_max_size, asg_desired_capacity도 설정해야합니다.
- eks.tf
```

locals {
  cluster_name = "test-eks-${random_string.suffix.result}"
  worker_groups = [
    {
      instance_type       = "t2.small"
      subnets             = "${join(",", module.vpc.private_subnets)}"
      asg_min_size = 2
      asg_max_size = 10
      asg_desired_capacity = 2
      autoscaling_enabled = true
      protect_from_scale_in = true
    },
  ]
    :
}
    :

```

```
$ terraform apply
```
그러면 cluster-autoscaler-status에 NodeGroups이 추가됩니다.

```
$ kubectl -n kube-system describe configmaps cluster-autoscaler-status
Name:         cluster-autoscaler-status
Namespace:    kube-system
Labels:       <none>
Annotations:  cluster-autoscaler.kubernetes.io/last-updated: 2018-12-31 03:34:54.585531666 +0000 UTC

Data
====
status:
----
Cluster-autoscaler status at 2018-12-31 03:34:54.585531666 +0000 UTC:
Cluster-wide:
  Health:      Healthy (ready=2 unready=0 notStarted=0 longNotStarted=0 registered=2 longUnregistered=0)
               LastProbeTime:      2018-12-31 03:34:54.458541261 +0000 UTC m=+1062.015991044
               LastTransitionTime: 2018-12-31 03:17:22.931577808 +0000 UTC m=+10.489027591
  ScaleUp:     NoActivity (ready=2 registered=2)
               LastProbeTime:      2018-12-31 03:34:54.458541261 +0000 UTC m=+1062.015991044
               LastTransitionTime: 2018-12-31 03:17:22.931577808 +0000 UTC m=+10.489027591
  ScaleDown:   NoCandidates (candidates=0)
               LastProbeTime:      2018-12-31 03:34:54.458541261 +0000 UTC m=+1062.015991044
               LastTransitionTime: 2018-12-31 03:17:22.931577808 +0000 UTC m=+10.489027591

NodeGroups:
  Name:        test-eks-pSfTUN5w-02018123102273646430000000f
  Health:      Healthy (ready=2 unready=0 notStarted=0 longNotStarted=0 registered=2 longUnregistered=0 cloudProviderTarget=2 (minSize=2, maxSize=10))
               LastProbeTime:      2018-12-31 03:34:54.458541261 +0000 UTC m=+1062.015991044
               LastTransitionTime: 2018-12-31 03:32:31.956211675 +0000 UTC m=+919.513661423
  ScaleUp:     NoActivity (ready=2 cloudProviderTarget=2)
               LastProbeTime:      2018-12-31 03:34:54.458541261 +0000 UTC m=+1062.015991044
               LastTransitionTime: 2018-12-31 03:32:31.956211675 +0000 UTC m=+919.513661423
  ScaleDown:   NoCandidates (candidates=0)
               LastProbeTime:      2018-12-31 03:34:54.458541261 +0000 UTC m=+1062.015991044
               LastTransitionTime: 2018-12-31 03:32:31.956211675 +0000 UTC m=+919.513661423


Events:  <none>
```
CA의 동작 확인은 마지막에 실시합니다.

#### 참고
- [cluster-autoscaler](https://github.com/helm/charts/tree/master/stable/cluster-autoscaler)


#### 보충 - k8s 클러스터 이름 검색
CA 설치를 자동화하려는 경우 k8s 클러스터 이름을 Terraform에서 얻을 수 있습니다.
이 경우 outputs.tf을 작성하고 다시 terraform apply를 실행 한 후 terraform output을 수행 할 수 있습니다.

- outputs.tf
```
output "cluster_name" {
  value = "${local.cluster_name}"
}
```

```
$ terraform apply
$ terraform output -json
{
    "cluster_name": {
        "sensitive": false,
        "type": "string",
        "value": "test-eks-pSfTUN5w"
    }
}
$ terraform output -json | jq -r '.cluster_name.value'
test-eks-pSfTUN5w
```

### AWS ALB Ingress Controller
#### 설치
k8s on AWS에서 ALB를 사용하려면 AWS ALB Ingress Controller를 설치해야합니다.
Setup ALB Ingress Controller를 참고로 Helm에 설치합니다.

- aws-alb-ingress-controller/values.yaml
```
autoDiscoverAwsRegion: true
autoDiscoverAwsVpcID: true
```

```
$ helm repo add \
    incubator http://storage.googleapis.com/kubernetes-charts-incubator
$ helm upgrade --install \
    aws-alb-ingress-controller \
    incubator/aws-alb-ingress-controller \
    --version 0.1.4 \
    --namespace kube-system \
    --values aws-alb-ingress-controller/values.yaml \
    --set clusterName=test-eks-pSfTUN5w
```

#### IAM Role 설정
이제 설치는 가능하지만 아직 ALB Ingress를 만들 수 없습니다.
이 상태로는 EKS가 ELB를 취급 권한이 없기 때문에, IAM Role을 추가해야합니다.

iam.tf라는 파일을 만들고 Terraform을 실행합니다.

- iam.tf
```
resource "aws_iam_role_policy_attachment" "alb_ingress_policy_attachment" {
  role = "${module.eks.worker_iam_role_name}"
  policy_arn = "${aws_iam_policy.alb_ingress_policy.arn}"
}

resource "aws_iam_policy" "alb_ingress_policy" {
  name = "alb-ingress-policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "acm:DescribeCertificate",
        "acm:ListCertificates",
        "acm:GetCertificate"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateSecurityGroup",
        "ec2:CreateTags",
        "ec2:DeleteTags",
        "ec2:DeleteSecurityGroup",
        "ec2:DescribeAccountAttributes",
        "ec2:DescribeAddresses",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVpcs",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifyNetworkInterfaceAttribute",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:AddTags",
        "elasticloadbalancing:CreateListener",
        "elasticloadbalancing:CreateLoadBalancer",
        "elasticloadbalancing:CreateRule",
        "elasticloadbalancing:CreateTargetGroup",
        "elasticloadbalancing:DeleteListener",
        "elasticloadbalancing:DeleteLoadBalancer",
        "elasticloadbalancing:DeleteRule",
        "elasticloadbalancing:DeleteTargetGroup",
        "elasticloadbalancing:DeregisterTargets",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeRules",
        "elasticloadbalancing:DescribeSSLPolicies",
        "elasticloadbalancing:DescribeTags",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetGroupAttributes",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:ModifyListener",
        "elasticloadbalancing:ModifyLoadBalancerAttributes",
        "elasticloadbalancing:ModifyRule",
        "elasticloadbalancing:ModifyTargetGroup",
        "elasticloadbalancing:ModifyTargetGroupAttributes",
        "elasticloadbalancing:RegisterTargets",
        "elasticloadbalancing:RemoveTags",
        "elasticloadbalancing:SetIpAddressType",
        "elasticloadbalancing:SetSecurityGroups",
        "elasticloadbalancing:SetSubnets",
        "elasticloadbalancing:SetWebACL"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole",
        "iam:GetServerCertificate",
        "iam:ListServerCertificates"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "waf-regional:GetWebACLForResource",
        "waf-regional:GetWebACL",
        "waf-regional:AssociateWebACL",
        "waf-regional:DisassociateWebACL"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "tag:GetResources",
        "tag:TagResources"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "waf:GetWebACL"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}
```

```
$ terraform apply
```
이제 ALB Ingress를 만들기위한 설정이 완료되었습니다.

#### 서브넷의 자동 검색 설정
지금 상태에서 Ingress를 작성하는 경우 매니페스트는 다음과 같습니다.

- ingress.yaml
```
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/subnets: subnet-aaa,subnet-bbb,subnet-ccc
  name: sample-app
spec:
  rules:
    - http:
        paths:
          - path: /
            backend:
              serviceName: sample-app
              servicePort: 80
```

이대로는 매니페스트에 서브넷 ID를 작성하는 것은 상당히 귀찮은 일입니다.
그래서 [Subnet Auto Discovery](https://kubernetes-sigs.github.io/aws-alb-ingress-controller/guide/controller/config/#subnet-auto-discovery)를 설정합니다.
vpc.tf을 수정하여 Private Subnet에 kubernetes.io/role/internal-elb, Public Subnet에 kubernetes.io/role/elb는 키 태그를 만듭니다.

- vpc.tf
```
    :
module "vpc" {
    :
  tags               = "${merge(local.tags, map("kubernetes.io/cluster/${local.cluster_name}", "shared"))}"
  private_subnet_tags  = {
    "kubernetes.io/role/internal-elb" = ""
  }
  public_subnet_tags   = {
    "kubernetes.io/role/elb" = ""
  }
}
```

```
$ terraform apply
```
이제 AWS ALB Ingress Controller의 설정이 완료 됐습니다.

#### 참고
[ALB Ingress Controller 사용](https://qiita.com/koudaiii/items/2031d67c715b5bb50357)

#### 주의
여기에서는 다루지 않지만, Route53과의 연계 및 ACM을 이용한 HTTPS를 실현하기 위해서는 추가 설정이 필요합니다.

### Deployment、Service、Ingress、HPA 작성
지금까지 설정이 끝났다면, 오토 스케일 Web 응용 프로그램을 배포 할 수 있습니다.
Deployment, Service, Ingress, HPA의 4개의 매니페스트를 만듭니다.

- deployment.yaml
```
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: sample-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sample-app
  minReadySeconds: 5
  progressDeadlineSeconds: 60
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 50%
      maxUnavailable: 50%
  template:
    metadata:
      labels:
        app: sample-app
    spec:
      terminationGracePeriodSeconds: 60
      containers:
      - name: sample-app
        image: nginx:1.15.8-alpine
        livenessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 5
          timeoutSeconds: 10
          periodSeconds: 10
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 5
          timeoutSeconds: 10
          periodSeconds: 10
          failureThreshold: 3
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 500m
            memory: 512Mi
```

- service.yaml
```
---
apiVersion: v1
kind: Service
metadata:
  name: sample-app
spec:
  selector:
    app: sample-app
  ports:
    - name: sample-app
      port: 80
      targetPort: 80
  type: NodePort
```

- ingress.yaml
```
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
  name: sample-app
spec:
  rules:
    - http:
        paths:
          - path: /
            backend:
              serviceName: sample-app
              servicePort: 80
```

- hpa.yaml
```
---
apiVersion: autoscaling/v2beta1
kind: HorizontalPodAutoscaler
metadata:
  name: sample-app
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sample-app
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      targetAverageUtilization: 10
```

kubectl 로 배포 합니다.
```
$ ls
deployment.yaml hpa.yaml        ingress.yaml    service.yaml
$ kubectl apply -R -f .
deployment.extensions/sample-app created
horizontalpodautoscaler.autoscaling/sample-app created
ingress.extensions/sample-app created
service/sample-app created
$ kubectl get all
NAME                              READY   STATUS    RESTARTS   AGE
pod/sample-app-665765dbcd-kqd9g   1/1     Running   0          24s
pod/sample-app-665765dbcd-vl6nm   1/1     Running   0          24s

NAME                 TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
service/kubernetes   ClusterIP   172.20.0.1      <none>        443/TCP        2h
service/sample-app   NodePort    172.20.100.78   <none>        80:30913/TCP   23s

NAME                         DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/sample-app   2         2         2            2           24s

NAME                                    DESIRED   CURRENT   READY   AGE
replicaset.apps/sample-app-665765dbcd   2         2         2       24s

NAME                                             REFERENCE               TARGETS         MINPODS   MAXPODS   REPLICAS   AGE
horizontalpodautoscaler.autoscaling/sample-app   Deployment/sample-app   <unknown>/10%   2         10        0          24s
```

Ingress는 시간이 걸립니다.
잠시 기다리면 무사 Ingress 통해 Nginx에 액세스 할 수 있습니다.
```
$ curl `kubectl get ingresses -o jsonpath --template {.items[0].status.loadBalancer.ingress[0].hostname}`
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

### 스케일링의 검증
HPA, CA의 검증을 위해 kubectl exec를 이용하여 컨테이너에서 CPU 사용률을 높여보십시오.

```
$ kubectl exec -it sample-app-665765dbcd-kqd9g sh
/ # yes > /dev/null
```

이대로 다른 터미널을 보면, Pod가 2 개에서 3 개로 오토 스케일합니다.
```
$ kubectl get all
NAME                              READY   STATUS    RESTARTS   AGE
pod/sample-app-665765dbcd-kqd9g   1/1     Running   0          12m
pod/sample-app-665765dbcd-m79hs   0/1     Pending   0          50s
pod/sample-app-665765dbcd-vl6nm   1/1     Running   0          12m

NAME                 TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
service/kubernetes   ClusterIP   172.20.0.1      <none>        443/TCP        2h
service/sample-app   NodePort    172.20.100.78   <none>        80:30913/TCP   12m

NAME                         DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/sample-app   3         3         3            2           12m

NAME                                    DESIRED   CURRENT   READY   AGE
replicaset.apps/sample-app-665765dbcd   3         3         2       12m

NAME                                             REFERENCE               TARGETS   MINPODS   MAXPODS   REPLICAS   AGE
horizontalpodautoscaler.autoscaling/sample-app   Deployment/sample-app   50%/10%   2         10        3          12m
```

HPA에서 만든 Pod의 STATUS는 Pending을 위해 CA에서 노드 추가가 이루어지는 것입니다.
cluster-autoscaler-status를 보면 ...
```
$ kubectl -n kube-system describe configmaps cluster-autoscaler-status
Name:         cluster-autoscaler-status
Namespace:    kube-system
Labels:       <none>
Annotations:  cluster-autoscaler.kubernetes.io/last-updated: 2018-12-31 04:47:06.27366144 +0000 UTC

Data
====
status:
----
Cluster-autoscaler status at 2018-12-31 04:47:06.27366144 +0000 UTC:
Cluster-wide:
  Health:      Healthy (ready=3 unready=0 notStarted=0 longNotStarted=0 registered=3 longUnregistered=0)
               LastProbeTime:      2018-12-31 04:47:06.088555494 +0000 UTC m=+5393.646005236
               LastTransitionTime: 2018-12-31 03:17:22.931577808 +0000 UTC m=+10.489027591
  ScaleUp:     NoActivity (ready=3 registered=3)
               LastProbeTime:      2018-12-31 04:47:06.088555494 +0000 UTC m=+5393.646005236
               LastTransitionTime: 2018-12-31 04:47:06.088555494 +0000 UTC m=+5393.646005236
  ScaleDown:   NoCandidates (candidates=0)
               LastProbeTime:      2018-12-31 04:47:06.088555494 +0000 UTC m=+5393.646005236
               LastTransitionTime: 2018-12-31 04:47:06.088555494 +0000 UTC m=+5393.646005236

NodeGroups:
  Name:        test-eks-pSfTUN5w-02018123102273646430000000f
  Health:      Healthy (ready=3 unready=0 notStarted=0 longNotStarted=0 registered=3 longUnregistered=0 cloudProviderTarget=3 (minSize=2, maxSize=10))
               LastProbeTime:      2018-12-31 04:47:06.088555494 +0000 UTC m=+5393.646005236
               LastTransitionTime: 2018-12-31 03:32:31.956211675 +0000 UTC m=+919.513661423
  ScaleUp:     NoActivity (ready=3 cloudProviderTarget=3)
               LastProbeTime:      2018-12-31 04:47:06.088555494 +0000 UTC m=+5393.646005236
               LastTransitionTime: 2018-12-31 04:47:06.088555494 +0000 UTC m=+5393.646005236
  ScaleDown:   NoCandidates (candidates=0)
               LastProbeTime:      2018-12-31 04:47:06.088555494 +0000 UTC m=+5393.646005236
               LastTransitionTime: 2018-12-31 04:47:06.088555494 +0000 UTC m=+5393.646005236


Events:
  Type    Reason         Age    From                Message
  ----    ------         ----   ----                -------
  Normal  ScaledUpGroup  2m22s  cluster-autoscaler  Scale-up: setting group test-eks-pSfTUN5w-02018123102273646430000000f size to 3
  Normal  ScaledUpGroup  2m22s  cluster-autoscaler  Scale-up: group test-eks-pSfTUN5w-02018123102273646430000000f size set to 3
```

Scale-up 이벤트가 발생하고 있습니다.

잠시 기다리면 Pod 노드 모두 오토 스케일 된 것을 확인할 수 있습니다.
HPA, CA, ALB Ingress까지 무사히 도입되었습니다.

### 정리
```
$ kubectl delete deployment sample-app
$ kubectl delete service sample-app
$ kubectl delete ingress sample-app
$ kubectl delete hpa sample-app
$ helm delete --purge `helm ls -aq`
$ terraform destroy
```
※ AutoScalingGroup는 수동으로 제거하지 않으면 terraform destory에 실패 할지도 모릅니다.

