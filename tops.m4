#!/bin/bash

# m4_ignore(
echo "This is just a script template, not the script (yet) - pass it to 'argbash' to fix this." >&2
exit 11  #)Created by argbash-init v2.10.0
# ARG_OPTIONAL_SINGLE([env-file], e, [Environment file], "${HOME}/.env")
# ARG_POSITIONAL_SINGLE([workspace-path],[Workspace path],"${PWD}")
# ARG_DEFAULTS_POS
# ARG_HELP([<The general help message of my script>])
# ARGBASH_GO

# [ <-- needed because of Argbash

# vvv  PLACE YOUR CODE HERE  vvv
# For example:
printf 'Value of --%s: %s\n' 'Environment file' "$_arg_env_file"
printf "Value of '%s': %s\\n" 'Workspace path' "$_arg_workspace_path"
CONTAINER_UUID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)
USER_ID=$(id -u)

{ docker build -t tops --build-arg USER_ID=${USER_ID} -f - . <<-\EOF
  FROM ubuntu:20.04

  ARG GOLANG_VERSION=1.14
  ARG SOPS_VERSION=3.5.0
  ARG HELM_VERSION=3.5.4
  ARG K8S_VERSION=1.19.0
  ARG K9S_VERSION=0.19.5
  ARG TERRAFORM_VERSION=0.14.6
  ARG TERRAFORM_PROVIDER_KUBECTL_VERSION=1.3.1
  ARG TERRAFORM_PROVIDER_SOPS_VERSION=0.5.0
  ARG DRIFTCTL_VERSION=0.9.0
  ARG ANSIBLE_VERSION=3.3.0
  ARG OPENSHIFT_VERSION=0.11.0 #https://github.com/kubernetes-client/python/issues/1333
  ARG KUBERNETES_PYTHON_VERSION=11.0.0
  ARG LOCALE_SETUP=en_US.UTF-8
  ARG RKE_VERSION=1.2.11
  ARG ISTIO_VERSION=1.11.2
  ARG CALICOCTL_VERSION=v3.19.1
  ARG USER_ID

  RUN useradd -u ${USER_ID} -s /bin/bash -d /home/tops -m tops

  RUN apt-get update && \
      apt-get install -y locales tzdata && \
      locale-gen ${LOCALE_SETUP} && \
      echo "export LC_ALL=${LOCALE_SETUP}" >> /home/tops/.bashrc

  RUN apt-get update && \
      apt-get install -y curl wget git gcc software-properties-common bash-completion \
                         unzip jq vim groff python3-pip dnsutils iputils-ping \
                         rsync lastpass-cli && \
      echo 'source /usr/share/bash-completion/bash_completion' >> /home/tops/.bashrc

  RUN add-apt-repository --yes --update ppa:longsleep/golang-backports && \
      apt-get install -y golang-${GOLANG_VERSION}-go

  ENV GOPATH /go
  ENV PATH $GOPATH/bin:/usr/lib/go-${GOLANG_VERSION}/bin:$PATH

  RUN curl -Ls https://github.com/mozilla/sops/releases/download/v${SOPS_VERSION}/sops_${SOPS_VERSION}_amd64.deb -o /tmp/sops.deb && \
      dpkg -i /tmp/sops.deb && \
      rm -fr /tmp/sops.deb

  RUN curl -Ls https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz | tar -zx -f - linux-amd64/helm --strip-components=1 && \
      mv helm /usr/local/bin/ && \
      helm plugin install https://github.com/zendesk/helm-secrets

  RUN curl -Ls https://github.com/camptocamp/helm-sops/releases/download/20201003-1/helm-sops_20201003-1_linux_amd64.tar.gz | tar -zx -C /usr/local/bin && \
      mv /usr/local/bin/helm /usr/local/bin/_helm && \
      mv /usr/local/bin/helm-sops /usr/local/bin/helm && \
      chmod a+x /usr/local/bin/helm

  RUN curl -Ls https://storage.googleapis.com/kubernetes-release/release/v${K8S_VERSION}/bin/linux/amd64/kubectl -o /usr/local/bin/kubectl && \
      chmod +x /usr/local/bin/kubectl && \
      echo 'source <(kubectl completion bash)' >> /home/tops/.bashrc && \
      echo 'alias k=kubectl' >> /home/tops/.bashrc && \
      echo 'complete -F __start_kubectl k' >> /home/tops/.bashrc

  RUN curl -Ls https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip | gunzip > /usr/local/bin/terraform && \
      chmod +x /usr/local/bin/terraform && \
      mkdir -p /home/tops/.terraform.d/plugins && \
      terraform -install-autocomplete

  RUN curl -Ls https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip && \
      unzip -q /tmp/awscliv2.zip -d /tmp && \
      /tmp/aws/install && \
      rm -fr /tmp/aw* && \
      echo "complete -C '/usr/local/bin/aws_completer' aws" >> /home/tops/.bashrc

  RUN curl -Ls https://github.com/gavinbunney/terraform-provider-kubectl/releases/download/v${TERRAFORM_PROVIDER_KUBECTL_VERSION}/terraform-provider-kubectl-linux-amd64 \
           -o /home/tops/.terraform.d/plugins/terraform-provider-kubectl_v${TERRAFORM_PROVIDER_KUBECTL_VERSION} && \
      chmod +x /home/tops/.terraform.d/plugins/terraform-provider-kubectl_v${TERRAFORM_PROVIDER_KUBECTL_VERSION}

  RUN curl -Ls https://github.com/carlpett/terraform-provider-sops/releases/download/v${TERRAFORM_PROVIDER_SOPS_VERSION}/terraform-provider-sops_v${TERRAFORM_PROVIDER_SOPS_VERSION}_linux_amd64.zip \
           -o /tmp/terraform-provider-sops.zip && \
      unzip -j /tmp/terraform-provider-sops.zip -d /home/tops/.terraform.d/plugins/ && \
      chmod +x /home/tops/.terraform.d/plugins/terraform-provider-sops_v${TERRAFORM_PROVIDER_SOPS_VERSION}

  RUN curl -Ls https://github.com/derailed/k9s/releases/download/v${K9S_VERSION}/k9s_Linux_x86_64.tar.gz | tar -zx k9s && \
      mv k9s /usr/local/bin/

  RUN curl -Ls https://github.com/rancher/rke/releases/download/v${RKE_VERSION}/rke_linux-amd64 \
           -o /usr/local/bin/rke && \
           chmod a+x /usr/local/bin/rke

  RUN pip3 install \
              ansible==${ANSIBLE_VERSION} \
              boto3 \
              kubernetes==${KUBERNETES_PYTHON_VERSION} \
              openshift==${OPENSHIFT_VERSION}

  RUN curl -L https://github.com/cloudskiff/driftctl/releases/download/v${DRIFTCTL_VERSION}/driftctl_linux_amd64 -o /usr/local/bin/driftctl && \
      chmod a+x /usr/local/bin/driftctl

  RUN curl -Ls https://github.com/turbot/steampipe/releases/latest/download/steampipe_linux_amd64.tar.gz -o /tmp/steampipe.tar.gz && \
      mkdir /tmp/steampipetemp && \
      tar -xf /tmp/steampipe.tar.gz -C /tmp/steampipetemp && \
      install /tmp/steampipetemp/steampipe /usr/local/bin/steampipe && \
      chmod a+x /usr/local/bin/steampipe && \
      rm -rf /tmp/steampipe*

  RUN curl -L https://github.com/istio/istio/releases/download/${ISTIO_VERSION}/istio-${ISTIO_VERSION}-linux-amd64.tar.gz | tar -zx -C /usr/local/src && \
      echo "export PATH=$PATH:/usr/local/src/istio-${ISTIO_VERSION}/bin" >> /home/tops/.bashrc && \
      chmod a+rx /usr/local/src/istio-${ISTIO_VERSION} && chmod a+rx /usr/local/src/istio-${ISTIO_VERSION}/bin && \
      chmod a+rx /usr/local/src/istio-${ISTIO_VERSION}/bin/istioctl && \
      ln -s /usr/local/src/istio-${ISTIO_VERSION}/bin/istioctl /usr/local/bin/istioctl

  RUN curl -Ls "https://github.com/projectcalico/calicoctl/releases/download/${CALICOCTL_VERSION}/calicoctl" -o /usr/local/bin/calicoctl && \
      chmod a+rx /usr/local/bin/calicoctl

  RUN mkdir -p /home/tops/.ssh && \
      echo 'PubkeyAcceptedKeyTypes +ssh-dss-cert-v01@openssh.com' >> /home/tops/.ssh/config

  RUN chown -R tops:tops /home/tops

  USER tops

  RUN steampipe plugin install steampipe && \
      steampipe plugin install aws

  WORKDIR /workspace

EOF
} && \
docker run \
  --rm \
  -v ${_arg_workspace_path}:/workspace \
  -v ${HOME}/.aws/credentials:/home/tops/.aws/credentials:ro \
  -v ${HOME}/.kube:/home/tops/.kube:ro \
  -v ${SSH_AUTH_SOCK}:/my_ssh_auth_sock \
  -v ${HOME}/.terraformrc:/home/tops/.terraformrc:ro \
  -v ${HOME}/.terraform.d/plugin-cache:/home/tops/.terraform.d/plugin-cache \
  -v ${HOME}/.vault_password_file:/home/tops/.vault_password_file \
  --env SSH_AUTH_SOCK=/my_ssh_auth_sock \
  --name tops-${CONTAINER_UUID} \
  --env-file $_arg_env_file \
  -ti \
  tops
# ^^^  TERMINATE YOUR CODE BEFORE THE BOTTOM ARGBASH MARKER  ^^^

# ] <-- needed because of Argbash
