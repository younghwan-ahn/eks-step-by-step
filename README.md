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
* aws-iam-authenticator
* heptio-authenticator-aws에서 이름이 바뀌어 있기 때문에주의하십시오
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










