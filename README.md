# rauth - Registry Authentication Service

基于 Kubernetes namespace 的 Docker Registry 鉴权服务。每个 namespace 只能拉取属于自己 namespace 的镜像。

## 功能

- 基于 Kubernetes namespace 的镜像访问控制
- 支持 Docker Registry Token Authentication 协议
- 从 namespace 中的 Secret 读取凭证
- 支持 JWT Token 生成和验证

## 架构

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │───>│  Registry   │───>│   rauth     │
│ (kubelet)   │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                          │                  │
                          │                  │
                          ▼                  ▼
                   ┌─────────────┐    ┌─────────────┐
                   │   Images    │    │  K8s API    │
                   │   Storage   │    │  (Secrets)  │
                   └─────────────┘    └─────────────┘
```

## 工作流程

1. Pod 尝试拉取镜像 `internal-registry.io/namespace-a/myapp:v1`
2. Registry 返回 401，要求认证
3. kubelet 使用 imagePullSecrets 中的凭证请求 rauth 获取 token
4. rauth 验证：
   - 从请求中解析出目标 namespace (`namespace-a`)
   - 从 `namespace-a` 的 `registry-credentials` Secret 读取凭证
   - 验证请求中的用户名密码是否匹配
   - 确保请求的镜像属于该 namespace
5. 验证通过后，rauth 返回 JWT token
6. kubelet 使用 token 从 Registry 拉取镜像

## 部署

### 前置条件

- Kubernetes 集群
- Helm 3.x
- Docker Registry（部署在集群内或外部）
- 每个 namespace 需要有一个 controller 生成 `registry-credentials` Secret

### 使用 Helm 部署

```bash
# 添加本地 chart（如果已打包）
helm install rauth ./charts/rauth -n registry --create-namespace

# 或者使用自定义配置
helm install rauth ./charts/rauth -n registry --create-namespace \
  --set config.service=internal-registry.io \
  --set config.issuer=rauth \
  --set image.repository=your-registry/rauth \
  --set image.tag=v1.0.0
```

### Helm Values 配置

```yaml
# values.yaml 示例
replicaCount: 2

image:
  repository: internal-registry.io/registry/rauth
  tag: latest

config:
  port: 8080
  issuer: "rauth"
  service: "internal-registry.io"
  secretName: "registry-credentials"
  tokenExpiry: "5m"
  logLevel: "info"

# 可选：启用内置 Registry
registry:
  enabled: false
  storage:
    size: 10Gi
```

### 配置 Registry

Registry 需要配置 token 认证，指向 rauth 服务：

```yaml
auth:
  token:
    realm: http://rauth.registry.svc.cluster.local/token
    service: internal-registry.io
    issuer: rauth
    rootcertbundle: /etc/registry/certs/token.crt
```

### 配置 Namespace Secret

每个 namespace 需要有 controller 生成如下格式的 Secret：

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: registry-credentials
  namespace: <namespace-name>
type: Opaque
data:
  username: <base64-encoded-username>  # 建议使用 namespace 名称
  password: <base64-encoded-password>  # 随机生成的密码
```

同时生成对应的 imagePullSecret：

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: registry-pull-secret
  namespace: <namespace-name>
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded-docker-config>
```

## Helm Chart 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `replicaCount` | 2 | 副本数 |
| `image.repository` | internal-registry.io/registry/rauth | 镜像仓库 |
| `image.tag` | latest | 镜像标签 |
| `config.port` | 8080 | 服务端口 |
| `config.issuer` | rauth | Token 签发者 |
| `config.service` | internal-registry.io | Registry 服务名称 |
| `config.secretName` | registry-credentials | 凭证 Secret 名称 |
| `config.tokenExpiry` | 5m | Token 有效期 |
| `config.logLevel` | info | 日志级别 |
| `rbac.create` | true | 是否创建 RBAC 资源 |
| `serviceAccount.create` | true | 是否创建 ServiceAccount |
| `registry.enabled` | false | 是否部署内置 Registry |

## API

### GET /token

Token 请求端点，符合 Docker Registry Token Authentication 规范。

**请求参数：**

- `service`: Registry 服务名称
- `scope`: 访问范围，格式为 `repository:namespace/image:action`

**请求头：**

- `Authorization`: Basic 认证，格式为 `Basic base64(username:password)`

**响应：**

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300
}
```

### GET /health, GET /healthz

健康检查端点。

## 构建

```bash
# 本地构建
go build -o rauth ./cmd/rauth

# Docker 构建
docker build -t rauth:latest .

# 打包 Helm Chart
helm package ./charts/rauth
```

## 开发

```bash
# 运行测试
go test ./...

# 本地运行（需要 kubeconfig）
go run ./cmd/rauth -port 8080

# 验证 Helm Chart
helm lint ./charts/rauth
helm template rauth ./charts/rauth
```

## 许可证

MIT
